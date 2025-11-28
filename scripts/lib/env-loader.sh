#!/usr/bin/env bash

# Load env-style files that support `include <path>` directives.
# `path` is resolved relative to the repo root first, then the including file.
load_env_with_includes() {
  local root_dir="$1"
  local entry="$2"

  if [[ -z "${__ENV_LOADER_INITIALIZED:-}" ]]; then
    declare -gA __LOADED_ENV_FILES=()
    __ENV_LOADER_INITIALIZED=1
  fi

  _load_env_recursive() {
    local file="$1"
    if [[ "$file" != /* ]]; then
      file="$root_dir/$file"
    fi
    file=$(cd "$(dirname "$file")" && pwd)/$(basename "$file")
    if [[ ! -f "$file" ]]; then
      echo "⚠️  Env file '$file' not found" >&2
      return 1
    fi
    if [[ -n "${__LOADED_ENV_FILES[$file]+_}" ]]; then
      return 0
    fi
    __LOADED_ENV_FILES[$file]=1

    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
      case "$line" in
        ''|\#*) continue ;;
        include\ *)
          local inc=${line#include }
          inc=${inc//\"/}
          inc=${inc//\'/}
          if [[ "$inc" != /* ]]; then
            if [[ -f "$root_dir/$inc" ]]; then
              _load_env_recursive "$root_dir/$inc" || return 1
            else
              _load_env_recursive "$(dirname "$file")/$inc" || return 1
            fi
          else
            _load_env_recursive "$inc" || return 1
          fi
          ;;
        *)
          eval "$line"
          ;;
      esac
    done < "$file"
  }

  _load_env_recursive "$entry"
}
