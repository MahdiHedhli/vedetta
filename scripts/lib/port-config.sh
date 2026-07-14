#!/usr/bin/env bash
# Shared host-port parsing and probing for Vedetta setup/update scripts.
#
# This file deliberately does not source .env: it contains secrets and is data,
# not trusted shell code. The parser accepts the practical dotenv forms used by
# Docker Compose for numeric port values (whitespace, single/double quotes, and
# whitespace-delimited trailing comments). Exported shell variables take
# precedence over .env, matching Compose interpolation precedence.

vedetta_normalize_port() {
  local value="${1-}"

  case "${value}" in
    ''|*[!0-9]*) return 1 ;;
  esac

  # Avoid arithmetic treating a leading zero as octal, and reject oversized
  # numeric input before passing it to the shell's integer comparison.
  while [ "${#value}" -gt 1 ] && [ "${value#0}" != "${value}" ]; do
    value="${value#0}"
  done
  [ "${#value}" -le 5 ] || return 1
  [ "${value}" -ge 1 ] 2>/dev/null || return 1
  [ "${value}" -le 65535 ] 2>/dev/null || return 1

  printf '%s' "${value}"
}

# vedetta_dotenv_value <file> <key>
# Prints the last active assignment for key. Returns 1 when the key is absent.
vedetta_dotenv_value() {
  local file="$1" key="$2"
  [ -f "${file}" ] || return 1

  awk -v wanted="${key}" '
    {
      line = $0
      sub(/\r$/, "", line)
      if (line !~ ("^[[:space:]]*" wanted "[[:space:]]*=")) {
        next
      }

      sub("^[[:space:]]*" wanted "[[:space:]]*=[[:space:]]*", "", line)
      quote = substr(line, 1, 1)
      single_quote = sprintf("%c", 39)

      if (quote == "\"" || quote == single_quote) {
        remainder = substr(line, 2)
        closing = index(remainder, quote)
        if (closing == 0) {
          # Let strict numeric validation reject malformed quoted input.
          value = line
        } else {
          value = substr(remainder, 1, closing - 1)
          trailer = substr(remainder, closing + 1)
          sub(/^[[:space:]]*/, "", trailer)
          if (trailer != "" && substr(trailer, 1, 1) != "#") {
            value = line
          }
        }
      } else {
        # Compose treats # as an inline comment only when whitespace separates
        # it from an unquoted value. A leading # therefore represents empty.
        if (line ~ /^[[:space:]]*#/) {
          value = ""
        } else {
          sub(/[[:space:]]+#.*/, "", line)
          sub(/^[[:space:]]*/, "", line)
          sub(/[[:space:]]*$/, "", line)
          value = line
        }
      }

      found = 1
      last = value
    }
    END {
      if (!found) exit 1
      print last
    }
  ' "${file}"
}

# vedetta_resolve_port <key> <default> <dotenv-file>
# Exported shell variables win over .env. Empty values use the Compose `:-`
# default because docker-compose.yml interpolates these variables that way.
vedetta_resolve_port() {
  local key="$1" default="$2" file="$3" value="" source="default"

  case "${key}" in
    ''|*[!A-Z0-9_]*)
      echo "error: invalid environment key '${key}'" >&2
      return 2
      ;;
  esac

  if value="$(printenv "${key}" 2>/dev/null)"; then
    source="the shell environment"
  elif value="$(vedetta_dotenv_value "${file}" "${key}" 2>/dev/null)"; then
    source="${file}"
  else
    value="${default}"
  fi

  if [ -z "${value}" ]; then
    value="${default}"
  fi

  if ! value="$(vedetta_normalize_port "${value}")"; then
    echo "error: ${key} from ${source} must be an integer from 1 through 65535" >&2
    return 1
  fi
  printf '%s' "${value}"
}

vedetta_detect_port_probe_tool() {
  if command -v lsof >/dev/null 2>&1; then
    printf '%s' lsof
  elif command -v ss >/dev/null 2>&1; then
    printf '%s' ss
  elif command -v netstat >/dev/null 2>&1; then
    printf '%s' netstat
  fi
}

# vedetta_port_in_use <tool> <tcp|udp> <port>
# Checks only the local endpoint column. Each awk program consumes its full
# input, avoiding grep -q/pipefail SIGPIPE false negatives on large listings.
vedetta_port_in_use() {
  local tool="$1" proto="$2" port="$3"

  case "${proto}" in
    tcp|udp) ;;
    *) return 2 ;;
  esac

  case "${tool}" in
    lsof)
      if [ "${proto}" = udp ]; then
        lsof -nP -iUDP -Fn 2>/dev/null
      else
        lsof -nP -a -iTCP -sTCP:LISTEN -Fn 2>/dev/null
      fi | awk -v port="${port}" '
        /^n/ {
          local_endpoint = substr($0, 2)
          sub(/->.*/, "", local_endpoint)
          if (local_endpoint ~ ("[:.]" port "$")) found = 1
        }
        END { exit !found }
      '
      ;;
    ss)
      local ss_proto=u
      [ "${proto}" = tcp ] && ss_proto=t
      ss -Hln"${ss_proto}" 2>/dev/null | awk -v port="${port}" '
        $4 ~ ("[:.]" port "$") { found = 1 }
        END { exit !found }
      '
      ;;
    netstat)
      netstat -an 2>/dev/null | awk -v proto="${proto}" -v port="${port}" '
        $1 ~ ("^" proto) && $4 ~ ("[:.]" port "$") &&
          (proto == "udp" || $NF == "LISTEN") { found = 1 }
        END { exit !found }
      '
      ;;
    *)
      return 1
      ;;
  esac
}
