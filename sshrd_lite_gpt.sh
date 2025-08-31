#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'USAGE'
[-] Usage: sshrd_lite.sh [parameters]
[-] Basic Parameters |      Optional
----------------------------------------
 -p Product Name     | -m specify model version
 -s iOS Version      | -g decrypt with gaster
 -b Build Version    | -y 1/2 kairos/iBoot64Patcher
                     | -z 1/2 img4/img4tool
 -c SSH connection   |
----------------------------------------
[-] For more info see "ifirmware_parser.sh -h"
USAGE
  exit 1
}

die() { echo "[e] $*" >&2; exit 1; }
info() { echo "[-] $*"; }
warn() { echo "[!] $*"; }

# ---------- preflight ----------
[[ "${1-}" != "" ]] || { echo "For info please use 'sshrd_lite.sh -h'"; exit 1; }

# Create temp dir & ensure cleanup (also kills iproxy if we started it)
TMPDIR="$(mktemp -d -t sshrd.XXXXXX)"
IPROXY_PID=""
cleanup() {
  [[ -n "$IPROXY_PID" ]] && kill "$IPROXY_PID" 2>/dev/null || true
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

# Bootstrap helpers if missing
if [[ ! -s 'misc/platform_check.sh' || ! -s './ifirmware_parser.sh' ]]; then
  if [[ -s './ifirmware_parser/README.md' ]]; then
    info 'Setting up ifirmware parser (first run) ...'
    cp -f './ifirmware_parser/ifirmware_parser.sh' './'
    cp -f './ifirmware_parser/ca-bundle.crt' './'
    mkdir -p './misc'
    cp -f './ifirmware_parser/misc/platform_check.sh' './misc/platform_check.sh'
    cp -f './ifirmware_parser/misc/firmwares.json' './misc/firmwares.json'
  else
    warn 'Required module is missing ...'
    warn 'Downloading ifirmware parser module ...'
    warn 'Submodule link: https://github.com/mast3rz3ro/ifirmware_parser'
    git submodule update --init || die "Failed to init submodule"
    exit 1
  fi
fi

# Source platform/tool paths
# shellcheck source=/dev/null
source './misc/platform_check.sh'

chmod -R +x 'tools/' || true
chmod +x './ifirmware_parser.sh' './misc/platform_check.sh' './boot_sshrd.sh'

# ---------- args ----------
declare -a args=()
ssh_connect=""; pwndfu_decrypt=""
patch_iboot_with="kairos"
pack_ramdisk_with="img4"

while getopts ":p:m:s:b:y:z:cgh" option; do
  case "${option}" in
    p) args+=(-p "${OPTARG}") ;;
    m) args+=(-m "${OPTARG}") ;;
    s) args+=(-s "${OPTARG}") ;;
    b) args+=(-b "${OPTARG}") ;;
    y) patch_iboot_with="${OPTARG}" ;;
    z) pack_ramdisk_with="${OPTARG}" ;;
    c) ssh_connect="yes" ;;
    g) pwndfu_decrypt="yes" ;;
    h) usage ;;
    \?) usage ;;
  esac
done

# Normalize optional switches
patch_iboot_with=$([[ "$patch_iboot_with" == "2" ]] && echo "iBoot64Patcher" || echo "kairos")
pack_ramdisk_with=$([[ "$pack_ramdisk_with" == "2" ]] && echo "img4tool" || echo "img4")

# ---------- optional: SSH connect ----------
if [[ "$ssh_connect" == "yes" ]]; then
  [[ -n "${iproxy-}" ]]   || warn 'Warning: iproxy variable is not set!'
  [[ -n "${sshpass-}" ]]  || warn 'Warning: sshpass variable is not set!'
  if [[ -n "${iproxy-}" && -n "${sshpass-}" ]]; then
    sudo "$iproxy" 2222 22 &>/dev/null & IPROXY_PID="$!"
    sleep 0.3
    if check="$("$sshpass" -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "echo connected" 2>/dev/null)"; then
      [[ "$check" == "connected" ]] && exec "$sshpass" -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost
    elif [[ "${platform-}" == "Linux" ]]; then
      info 'Force closing usbmuxd ...'
      sudo systemctl stop usbmuxd || true
      sudo usbmuxd -p -f
    fi
  fi
  exit 0
fi

# ---------- dirs & inputs ----------
input_folder='1_prepare_ramdisk'
temp_folder='2_ssh_ramdisk/temp_files'
mkdir -p "$input_folder" "$temp_folder"

if [[ ! -s 'misc/sshtars/ssh.tar' ]]; then
  info 'Extracting sshtars ...'
  [[ -s './misc/sshtars/ssh.tar.xz' ]] || die "Missing misc/sshtars/ssh.tar.xz"
  tar -xvf './misc/sshtars/ssh.tar.xz'
  mv -f './ssh.tar' './misc/sshtars/ssh.tar'
fi
if [[ -s 'misc/sshtars/ssh.tar' && ! -s 'misc/sshtars/ssh.tar.gz' && "${platform-}" == 'Darwin' ]]; then
  info 'Compressing sshtars into gz (Darwin step for hdiutil)'
  gzip -9 -k './misc/sshtars/ssh.tar'
fi

# ---------- fetch firmware & keys ----------
export OPTIND=1
if [[ "$pwndfu_decrypt" == "yes" ]]; then
  # shellcheck source=/dev/null
  source './ifirmware_parser.sh' "${args[@]}" -r -o "$input_folder"
else
  # shellcheck source=/dev/null
  source './ifirmware_parser.sh' "${args[@]}" -k -r -o "$input_folder"
  [[ -n "${ibec_key-}" && -n "${ibss_key-}" ]] || die 'Decryption keys are not set!'
fi

# Compose version number safely (major*100 + minor), e.g., 15.10 -> 1510
major_ios_num=${major_ios:-0}
minor_ios_num=${minor_ios:-0}
check_ios_num=$(( major_ios_num*100 + minor_ios_num ))

# Build paths
input_folder="$input_folder/${product_name}_${product_model}_${build_version}"
mkdir -p "$input_folder"
output_folder="2_ssh_ramdisk/${product_name}_${product_model}_${build_version}"
mkdir -p "$output_folder"

ibec_file="$input_folder/$ibec_file"
ibss_file="$input_folder/$ibss_file"
iboot_file="$input_folder/$iboot_file"
kernel_file="$input_folder/$kernel_file"
ramdisk_file="$input_folder/$ramdisk_file"
trustcache_file="$input_folder/$trustcache_file"
devicetree_file="$input_folder/$devicetree_file"

# Boot args
if [[ "${cpid-}" == '0x8960' || "${cpid-}" == '0x7000' || "${cpid-}" == '0x7001' ]]; then
  boot_args='rd=md0 debug=0x2014e -v wdt=-1 nand-enable-reformat=1 -restore -n'
else
  boot_args='rd=md0 debug=0x2014e -v wdt=-1 -n'
fi

# ---------- tool sanity (after platform_check populated vars) ----------
need_tools=(img4 img4tool hfsplus kairos iBoot64Patcher KPlooshFinder kerneldiff gaster)
for t in "${need_tools[@]}"; do
  # Skip optional ones depending on choices/platform
  [[ "$t" == "img4tool" && "$pack_ramdisk_with" != "img4tool" ]] && continue
  [[ "$t" == "kairos" && "$patch_iboot_with" != "kairos" ]] && continue
  [[ "$t" == "iBoot64Patcher" && "$patch_iboot_with" != "iBoot64Patcher" ]] && continue
  command -v "${!t:-$t}" >/dev/null 2>&1 || warn "Missing tool path for $t (may be fine if unused)"
done

# ---------- SHSH ----------
"$img4tool" -e -s "misc/shsh/${cpid}.shsh" -m "$temp_folder/shsh.bin"
shsh_file="$temp_folder/shsh.bin"

# ---------- Decrypt iBSS/iBEC/iBoot ----------
if [[ "$pwndfu_decrypt" == "yes" ]]; then
  warn 'Decrypting with gaster... put device into DFU'
  [[ "${platform-}" == 'Linux' || "${platform-}" == 'Darwin' ]] && warn "Hint: If stuck, rerun with sudo"
  [[ "${platform-}" == 'Windows' ]] && warn "Hint: MSYS2 may hide output"
  "$gaster" pwn
  info "Copying iBoot files to temp"
  cp "$ibec_file" "$TMPDIR/iBEC.raw"
  cp "$ibss_file" "$TMPDIR/iBSS.raw"
  cp "$iboot_file" "$TMPDIR/iBoot.raw"
  "$gaster" decrypt "$TMPDIR/iBEC.raw" "$temp_folder/iBEC.dec"
  "$gaster" decrypt "$TMPDIR/iBSS.raw" "$temp_folder/iBSS.dec"
  "$gaster" decrypt "$TMPDIR/iBoot.raw" "$temp_folder/iBoot.dec"
else
  "$img4" -i "$ibec_file"  -o "$temp_folder/iBEC.dec"  -k "$ibec_key"
  "$img4" -i "$ibss_file"  -o "$temp_folder/iBSS.dec"  -k "$ibss_key"
  "$img4" -i "$iboot_file" -o "$temp_folder/iBoot.dec" -k "$iboot_key"
fi

# ---------- Patch iBoot family ----------
if (( check_ios_num >= 1500 )) && [[ "$patch_iboot_with" == "kairos" ]]; then
  info 'Patching iBoot files with kairos ...'
  "$kairos" "$temp_folder/iBSS.dec" "$temp_folder/iBSS.patched"
  "$kairos" "$temp_folder/iBEC.dec" "$temp_folder/iBEC.patched" -b "$boot_args"
  "$kairos" "$temp_folder/iBoot.dec" "$temp_folder/iBoot.patched"
else
  info 'Patching iBoot files with iBoot64Patcher ...'
  "$iBoot64Patcher" "$temp_folder/iBSS.dec" "$temp_folder/iBSS.patched"
  "$iBoot64Patcher" "$temp_folder/iBEC.dec" "$temp_folder/iBEC.patched" -b "$boot_args"
  "$iBoot64Patcher" "$temp_folder/iBoot.dec" "$temp_folder/iBoot.patched"
fi

# Pack iBoot family
"$img4" -i "$temp_folder/iBSS.patched"  -o "$output_folder/iBSS.img4"  -M "$shsh_file" -A -T ibss
"$img4" -i "$temp_folder/iBEC.patched"  -o "$output_folder/iBEC.img4"  -M "$shsh_file" -A -T ibec
"$img4" -i "$temp_folder/iBoot.patched" -o "$output_folder/iBoot.img4" -M "$shsh_file" -A -T ibot

# ---------- Kernel ----------
"$img4" -i "$kernel_file" -o "$temp_folder/kcache.raw"
"$KPlooshFinder" "$temp_folder/kcache.raw" "$temp_folder/kcache.patched"
info 'Searching for kernel differences (this may take a while) ...'
"$kerneldiff" "$temp_folder/kcache.raw" "$temp_folder/kcache.patched" "$temp_folder/kc.bpatch"

# Build img4 args array to add Linux -J cleanly
declare -a IMG4_ARGS=(-i "$kernel_file" -o "$output_folder/kernelcache.img4" -M "$shsh_file" -T rkrn -P "$temp_folder/kc.bpatch")
[[ "${platform-}" == 'Linux' ]] && IMG4_ARGS+=(-J)
"$img4" "${IMG4_ARGS[@]}"
info 'Patching kernel completed!'

# ---------- Devicetree / Trustcache ----------
"$img4" -i "$devicetree_file" -o "$output_folder/devicetree.img4" -M "$shsh_file" -T rdtr
if [[ -s "$trustcache_file" ]]; then
  info "Found trustcache file: $trustcache_file"
  "$img4" -i "$trustcache_file" -o "$output_folder/trustcache.img4" -M "$shsh_file" -T rtsc
fi

# ---------- RAMDISK ----------
"$img4" -i "$ramdisk_file" -o "$temp_folder/ramdisk.dmg"

if [[ "${platform-}" != 'Darwin' && $check_ios_num -lt 1601 ]]; then
  "$hfsplus" "$temp_folder/ramdisk.dmg" grow 210000000
  "$hfsplus" "$temp_folder/ramdisk.dmg" untar 'misc/sshtars/ssh.tar'
elif [[ "${platform-}" == 'Darwin' && $check_ios_num -ge 1601 ]]; then
  hdiutil attach -mountpoint '/tmp/SSHRD' "$temp_folder/ramdisk.dmg"
  hdiutil create -size 210m -imagekey diskimage-class=CRawDiskImage -format UDZO -fs HFS+ -layout NONE -srcfolder '/tmp/SSHRD' -copyuid root "$temp_folder/reassigned_ramdisk.dmg"
  hdiutil detach -force '/tmp/SSHRD'
  hdiutil attach -mountpoint '/tmp/SSHRD' "$temp_folder/reassigned_ramdisk.dmg"
  ./tools/Darwin/gtar -x --no-overwrite-dir -f 'misc/sshtars/ssh.tar.gz' -C '/tmp/SSHRD/'
  hdiutil detach -force '/tmp/SSHRD'
  hdiutil resize -sectors min "$temp_folder/reassigned_ramdisk.dmg"
elif [[ "${platform-}" == 'Darwin' && $check_ios_num -lt 1601 ]]; then
  warn 'Warning: creating RAMDISK may fail on iOS 11.3 or lower.'
  hdiutil resize -size 210MB "$temp_folder/ramdisk.dmg"
  hdiutil attach -mountpoint '/tmp/SSHRD' "$temp_folder/ramdisk.dmg"
  ./tools/Darwin/gtar -x --no-overwrite-dir -f 'misc/sshtars/ssh.tar.gz' -C '/tmp/SSHRD/'
  hdiutil detach -force '/tmp/SSHRD'
  hdiutil resize -sectors min "$temp_folder/ramdisk.dmg"
else
  warn "APFS handling not supported on this platform for iOS >= 16.1"
  die  "Please select iOS < 16.1 and try again."
fi

info 'Packing ramdisk into img4 ...'
if [[ "${platform-}" == 'Darwin' && $check_ios_num -ge 1601 ]]; then
  "$img4" -i "$temp_folder/reassigned_ramdisk.dmg" -o "$output_folder/ramdisk.img4" -M "$shsh_file" -A -T rdsk
elif [[ "${platform-}" == 'Windows' && "$pack_ramdisk_with" == 'img4tool' ]]; then
  warn 'You selected img4tool for packing (faster, but may not boot on some devices)'
  "$img4tool" -i "$temp_folder/ramdisk.dmg" -c "$output_folder/ramdisk.img4" -s "$shsh_file" -t rdsk
else
  "$img4" -i "$temp_folder/ramdisk.dmg" -o "$output_folder/ramdisk.img4" -M "$shsh_file" -A -T rdsk
fi

# ---------- Boot logo ----------
"$img4" -i 'misc/bootlogo.im4p' -o "$output_folder/logo.img4" -M "$shsh_file" -A -T rlgo

# ---------- Done ----------
info 'Cleaning temp directory ...'
rm -rf "$temp_folder"
echo '[!] All Tasks Completed !'
echo '[-] To boot this SSHRD please use: ./boot_sshrd.sh'
