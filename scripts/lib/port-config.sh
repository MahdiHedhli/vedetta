#!/usr/bin/env bash
# Shared host-port parsing and probing for Vedetta setup/update scripts.
#
# This file deliberately does not source .env: it contains secrets and is data,
# not trusted shell code. The parser accepts the practical dotenv forms used by
# Docker Compose for numeric port values (optional export, whitespace,
# single/double quotes, simple full-value references, and whitespace-delimited
# trailing comments). Exported shell variables take precedence over .env,
# matching Compose interpolation precedence.

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

# vedetta_dotenv_entry <file> <key>
# Prints quote-mode|value for the last active assignment. Keeping the quote mode
# lets the port resolver honor Compose's rule that single-quoted values are
# literal while unquoted and double-quoted values may reference another
# variable. Returns 1 when the key is absent.
vedetta_dotenv_entry() {
  local file="$1" key="$2"
  [ -f "${file}" ] || return 1

  awk -v wanted="${key}" '
    {
      line = $0
      sub(/\r$/, "", line)
      prefix = "^[[:space:]]*(export[[:space:]]+)?"
      if (line !~ (prefix wanted "[[:space:]]*=")) {
        next
      }

      sub(prefix wanted "[[:space:]]*=[[:space:]]*", "", line)
      quote = substr(line, 1, 1)
      single_quote = sprintf("%c", 39)
      mode = "unquoted"

      if (quote == "\"" || quote == single_quote) {
        mode = (quote == single_quote ? "single" : "double")
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
      last_mode = mode
    }
    END {
      if (!found) exit 1
      print last_mode "|" last
    }
  ' "${file}"
}

# vedetta_dotenv_value <file> <key>
# Prints the parsed, but not interpolated, value for callers that only need
# dotenv syntax handling.
vedetta_dotenv_value() {
  local entry
  entry="$(vedetta_dotenv_entry "$1" "$2")" || return 1
  printf '%s\n' "${entry#*|}"
}

# vedetta_dotenv_port_value <file> <key>
# Resolves full-value $NAME or ${NAME} references without evaluating .env as
# shell code. Compose interpolates each assignment when it is parsed, so this
# deliberately walks the file once and freezes references against earlier
# assignments rather than resolving them from the file's final state. More
# complex interpolation fails numeric validation instead of silently selecting
# a port that differs from Docker Compose.
vedetta_dotenv_port_value() {
  local file="$1" key="$2"
  [ -f "${file}" ] || return 1

  awk -v wanted="${key}" '
    {
      line = $0
      sub(/\r$/, "", line)
      sub(/^[[:space:]]*/, "", line)
      if (line ~ /^export[[:space:]]+/) {
        sub(/^export[[:space:]]+/, "", line)
      }
      equals = index(line, "=")
      if (!equals) next

      name = substr(line, 1, equals - 1)
      sub(/[[:space:]]*$/, "", name)
      if (name !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next

      line = substr(line, equals + 1)
      sub(/^[[:space:]]*/, "", line)
      quote = substr(line, 1, 1)
      single_quote = sprintf("%c", 39)
      mode = "unquoted"

      if (quote == "\"" || quote == single_quote) {
        mode = (quote == single_quote ? "single" : "double")
        remainder = substr(line, 2)
        closing = index(remainder, quote)
        if (closing == 0) {
          value = line
        } else {
          value = substr(remainder, 1, closing - 1)
          trailer = substr(remainder, closing + 1)
          sub(/^[[:space:]]*/, "", trailer)
          if (trailer != "" && substr(trailer, 1, 1) != "#") value = line
        }
      } else if (line ~ /^[[:space:]]*#/) {
        value = ""
      } else {
        sub(/[[:space:]]+#.*/, "", line)
        sub(/^[[:space:]]*/, "", line)
        sub(/[[:space:]]*$/, "", line)
        value = line
      }

      ref = ""
      if (mode != "single" && value ~ /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/) {
        ref = substr(value, 3, length(value) - 3)
      } else if (mode != "single" && value ~ /^\$[A-Za-z_][A-Za-z0-9_]*$/) {
        ref = substr(value, 2)
      }
      if (ref != "") {
        if (ref in ENVIRON) value = ENVIRON[ref]
        else if (ref in assigned) value = resolved[ref]
        else value = ""
      }

      assigned[name] = 1
      resolved[name] = value
      if (name == wanted) {
        found = 1
        selected = value
      }
    }
    END {
      if (!found) exit 1
      print selected
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
  elif value="$(vedetta_dotenv_port_value "${file}" "${key}" 2>/dev/null)"; then
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
# Returns 0 when occupied, 1 when confirmed free, and 2 when probing failed.
vedetta_port_in_use() {
  local tool="$1" proto="$2" port="$3" output="" status=0 ss_proto
  local stderr_file="" stderr_output=""

  case "${proto}" in
    tcp|udp) ;;
    *) return 2 ;;
  esac

  case "${tool}" in
    lsof)
      # lsof uses status 1 both for a clean no-match and for some execution
      # errors (for example, an unreadable kernel/process table). Preserve its
      # diagnostics so only an entirely empty status-1 result counts as free.
      stderr_file="$(mktemp "${TMPDIR:-/tmp}/vedetta-lsof.XXXXXX")" || return 2
      if [ "${proto}" = udp ]; then
        if output="$(lsof -nP -iUDP:"${port}" -Fn 2>"${stderr_file}")"; then
          status=0
        else
          status=$?
        fi
      else
        if output="$(lsof -nP -a -iTCP:"${port}" -sTCP:LISTEN -Fn 2>"${stderr_file}")"; then
          status=0
        else
          status=$?
        fi
      fi
      stderr_output="$(cat "${stderr_file}" 2>/dev/null)" || {
        rm -f "${stderr_file}"
        return 2
      }
      rm -f "${stderr_file}"

      if [ "${status}" -eq 1 ]; then
        [ -z "${output}" ] && [ -z "${stderr_output}" ] || return 2
        return 1
      fi
      [ "${status}" -eq 0 ] || return 2
      printf '%s\n' "${output}" | awk -v port="${port}" '
        /^n/ {
          local_endpoint = substr($0, 2)
          sub(/->.*/, "", local_endpoint)
          if (local_endpoint ~ ("[:.]" port "$")) found = 1
        }
        END { exit !found }
      '
      ;;
    ss)
      ss_proto=u
      [ "${proto}" = tcp ] && ss_proto=t
      if output="$(ss -Hln"${ss_proto}" 2>/dev/null)"; then
        status=0
      else
        status=$?
      fi
      [ "${status}" -eq 0 ] || return 2
      printf '%s\n' "${output}" | awk -v port="${port}" '
        $4 ~ ("[:.]" port "$") { found = 1 }
        END { exit !found }
      '
      ;;
    netstat)
      if output="$(netstat -an 2>/dev/null)"; then
        status=0
      else
        status=$?
      fi
      [ "${status}" -eq 0 ] || return 2
      printf '%s\n' "${output}" | awk -v proto="${proto}" -v port="${port}" '
        $1 ~ ("^" proto) && $4 ~ ("[:.]" port "$") &&
          (proto == "udp" || $NF == "LISTEN") { found = 1 }
        END { exit !found }
      '
      ;;
    *)
      return 2
      ;;
  esac
}
