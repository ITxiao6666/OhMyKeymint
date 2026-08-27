// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, Result};
use serde::Deserialize;

pub const APEX_INFO_LIST_PATH: &str = "/apex/apex-info-list.xml";
pub const BOOTSTRAP_APEX_INFO_LIST_PATH: &str = "/bootstrap-apex/apex-info-list.xml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApexInfo {
    pub module_name: String,
    pub version_code: String,
    pub is_active: bool,
    pub partition: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "apex-info-list")]
struct ApexInfoListXml {
    #[serde(rename = "apex-info", default)]
    apex_infos: Vec<ApexInfoXml>,
}

#[derive(Debug, Deserialize)]
struct ApexInfoXml {
    #[serde(rename = "@moduleName")]
    module_name: String,
    #[serde(rename = "@versionCode")]
    version_code: String,
    #[serde(rename = "@isActive")]
    is_active: bool,
    #[serde(rename = "@partition", default)]
    partition: String,
}

pub fn parse_apex_info_list_xml(xml: &str) -> Result<Vec<ApexInfo>> {
    let parsed: ApexInfoListXml =
        quick_xml::de::from_str(xml).context("failed to deserialize apex-info-list XML")?;
    Ok(parsed
        .apex_infos
        .into_iter()
        .map(|info| ApexInfo {
            module_name: info.module_name,
            version_code: info.version_code,
            is_active: info.is_active,
            partition: info.partition,
        })
        .collect())
}
