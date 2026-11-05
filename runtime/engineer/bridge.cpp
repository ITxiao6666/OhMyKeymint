// App-local Java hook glue. Selection remains in OMK's Rust configuration path.
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <string_view>
#include <vector>
#include "dobby.h"
#include "lsplant.hpp"
#include "engineer_dex.h"

namespace {
struct ArtSymbols {
    std::vector<unsigned char> image;
    uintptr_t base = 0;

    bool load() {
        FILE* maps = fopen("/proc/self/maps", "re");
        if (!maps) return false;
        char line[4096], path[2048] = {};
        unsigned long start, end, offset;
        while (fgets(line, sizeof(line), maps)) {
            char candidate[2048] = {};
            if (sscanf(line, "%lx-%lx %*4s %lx %*s %*s %2047s", &start, &end, &offset, candidate) == 4
                    && std::string_view(candidate).ends_with("/libart.so") && offset == 0) {
                base = start;
                std::strcpy(path, candidate);
                break;
            }
        }
        fclose(maps);
        if (!base) return false;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        struct stat st {};
        if (fstat(fd, &st) || st.st_size <= 0 || st.st_size > 128 * 1024 * 1024) {
            close(fd); return false;
        }
        image.resize(st.st_size);
        size_t done = 0;
        while (done < image.size()) {
            ssize_t count = read(fd, image.data() + done, image.size() - done);
            if (count <= 0) break;
            done += count;
        }
        close(fd);
        return done == image.size();
    }

    void* find(std::string_view name, bool prefix) const {
        if (image.size() < sizeof(Elf64_Ehdr)) return nullptr;
        const auto* header = reinterpret_cast<const Elf64_Ehdr*>(image.data());
        if (memcmp(header->e_ident, ELFMAG, SELFMAG) || header->e_ident[EI_CLASS] != ELFCLASS64
                || header->e_shentsize != sizeof(Elf64_Shdr)
                || header->e_shoff > image.size()
                || header->e_shnum > (image.size() - header->e_shoff) / sizeof(Elf64_Shdr)) return nullptr;
        const auto* sections = reinterpret_cast<const Elf64_Shdr*>(image.data() + header->e_shoff);
        for (size_t i = 0; i < header->e_shnum; ++i) {
            const auto& section = sections[i];
            if ((section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM)
                    || section.sh_entsize != sizeof(Elf64_Sym) || section.sh_link >= header->e_shnum
                    || section.sh_offset > image.size() || section.sh_size > image.size() - section.sh_offset) continue;
            const auto& strings = sections[section.sh_link];
            if (strings.sh_offset > image.size() || strings.sh_size > image.size() - strings.sh_offset) continue;
            const auto* symbols = reinterpret_cast<const Elf64_Sym*>(image.data() + section.sh_offset);
            for (size_t j = 0; j < section.sh_size / sizeof(Elf64_Sym); ++j) {
                const auto& symbol = symbols[j];
                if (!symbol.st_value || symbol.st_shndx == SHN_UNDEF || symbol.st_name >= strings.sh_size) continue;
                const char* text = reinterpret_cast<const char*>(image.data() + strings.sh_offset + symbol.st_name);
                const void* nul = memchr(text, 0, strings.sh_size - symbol.st_name);
                if (!nul) continue;
                std::string_view candidate(text, static_cast<const char*>(nul) - text);
                if (prefix ? candidate.starts_with(name) : candidate == name)
                    return reinterpret_cast<void*>(base + symbol.st_value);
            }
        }
        return nullptr;
    }
};

jobject hook(JNIEnv* env, jclass, jobject target, jobject owner, jobject callback) {
    return lsplant::Hook(env, target, owner, callback);
}
jboolean deoptimize(JNIEnv* env, jclass, jobject method) {
    return lsplant::Deoptimize(env, method);
}
} // namespace

extern "C" __attribute__((visibility("default"))) bool omk_engineer_install(
        JNIEnv* env, const uint8_t* dex, size_t length, void* selected) {
    dex = omk_engineer_dex;
    length = sizeof(omk_engineer_dex);
    static ArtSymbols symbols;
    if (!symbols.load()) return false;
    const lsplant::InitInfo info {
        .inline_hooker = [](void* target, void* replacement) -> void* {
            void* original = nullptr;
            return DobbyHook(target, replacement, &original) == 0 ? original : nullptr;
        },
        .inline_unhooker = [](void* target) { return DobbyDestroy(target) == 0; },
        .art_symbol_resolver = [](std::string_view name) { return symbols.find(name, false); },
        .art_symbol_prefix_resolver = [](std::string_view name) { return symbols.find(name, true); },
        .generated_class_name = "OmkEngineerDisplay_",
        .generated_source_name = "OMK EngineerMode display",
        .generated_field_name = "hooker",
        .generated_method_name = "{target}",
        .executable_memory_allocator = {},
        .executable_memory_recycler = {}
    };
    if (!lsplant::Init(env, info)) return false;
    jobject buffer = env->NewDirectByteBuffer(const_cast<uint8_t*>(dex), length);
    if (env->ExceptionCheck() || !buffer) return false;
    jclass loader_class = env->FindClass("java/lang/ClassLoader");
    if (env->ExceptionCheck() || !loader_class) return false;
    jmethodID system_loader = env->GetStaticMethodID(loader_class, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    if (env->ExceptionCheck() || !system_loader) return false;
    jobject parent = env->CallStaticObjectMethod(loader_class, system_loader);
    if (env->ExceptionCheck() || !parent) return false;
    jclass memory_loader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (env->ExceptionCheck() || !memory_loader) return false;
    jmethodID ctor = env->GetMethodID(memory_loader, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (env->ExceptionCheck() || !ctor) return false;
    jobject loader = env->NewObject(memory_loader, ctor, buffer, parent);
    if (env->ExceptionCheck() || !loader) return false;
    jmethodID load_class = env->GetMethodID(loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (env->ExceptionCheck() || !load_class) return false;
    jstring name = env->NewStringUTF("omk.engineer.EngineerDisplay");
    if (env->ExceptionCheck() || !name) return false;
    auto bridge = static_cast<jclass>(env->CallObjectMethod(loader, load_class, name));
    if (env->ExceptionCheck() || !bridge) return false;
    JNINativeMethod methods[] = {
        {const_cast<char*>("hook"), const_cast<char*>("(Ljava/lang/reflect/Method;Ljava/lang/Object;Ljava/lang/reflect/Method;)Ljava/lang/reflect/Method;"), reinterpret_cast<void*>(hook)},
        {const_cast<char*>("deoptimize"), const_cast<char*>("(Ljava/lang/reflect/Method;)Z"), reinterpret_cast<void*>(deoptimize)},
        {const_cast<char*>("selected"), const_cast<char*>("()Z"), selected}
    };
    if (env->RegisterNatives(bridge, methods, 3) != 0) return false;
    jmethodID install = env->GetStaticMethodID(bridge, "install", "()V");
    if (!install) return false;
    env->CallStaticVoidMethod(bridge, install);
    return !env->ExceptionCheck();
}
