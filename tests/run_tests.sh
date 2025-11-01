start=0
end=0
passed=0
total=0
failed=()

function run_linux_test {
  ((++total))

  vm="$1"
  img="$2"
  plat="$3"

  if docker image inspect "$vm" > /dev/null 2>&1; then
    docker image rm "$vm" -f
    echo ""
  fi

  docker build -f linux/Dockerfile .. --tag $vm --platform=$plat --build-arg BASE_IMAGE=$img
  if test $? -ne 0; then
    echo "Errors in tests from: $vm. Could not build docker image."
    failed+=("$vm")
  fi
  echo ""

  echo "Running tests from: $vm..."
  docker run --rm -it $vm
  result=$?
  echo ""

  if test $result -eq 0; then
    echo "Successfully run tests from: $vm."
    ((++passed))
  else
    echo "Errors in tests from: $vm."
    failed+=("$vm")
  fi
  echo ""

  docker image rm $vm -f
  echo ""
}

function run_windows_test {
  ((++total))

  vm="$1"
  user="$2"
  pwd="$3"
  winnt=$4

  cfs_dir="$(dirname "$(dirname "$(readlink -fm "$0")")")"
  shared=CFSTestShare

  function _run_cmd {
    VBoxManage guestcontrol "$vm" run         \
      --exe "C:\\Windows\\System32\\cmd.exe"  \
      --username "$user"                      \
      --password "$pwd"                       \
      --wait-stdout                           \
      --wait-stderr                           \
      --timeout 30000                         \
      -- /c "$1"
  }

  function _shutdown {
    VBoxManage controlvm "$vm" acpipowerbutton
  }

  VBoxManage startvm "$vm" --type headless
  if test $? -ne 0; then
    echo "Errors in tests from: $vm. Could not start vm."
    failed+=("$vm")
    return
  fi
  echo ""

  VBoxManage guestproperty wait "$vm" "/VirtualBox/GuestAdd/Revision" \
      --timeout 60000
  if test $? -ne 0; then
    echo "Error in tests from: $vm. Timed out waiting for guest additions"
    failed+=("$vm")

    _shutdown
    return
  fi
  echo ""

  VBoxManage sharedfolder add "$vm" \
    --name $shared                  \
    --hostpath "$cfs_dir"           \
    --transient                     \
    --automount                     \
    --readonly
  if test $? -ne 0; then
    echo "Errors in tests from: $vm. Could not add shared folder."
    failed+=("$vm")

    _shutdown
    return
  fi
  echo ""

  sleep 10  # TODO: reliable wait for complete boot

  _run_cmd "mkdir C:\\cfs\\tests"
  _run_cmd "xcopy \\\\vboxsvr\\CFSTestShare\\tests\\* C:\\cfs\\tests\\ /E /C /I /Y"
  if test $? -ne 0; then
    echo "Errors in tests from: $vm. Could copy shared folder."
    failed+=("$vm")

    _run_cmd "rmdir /S /Q C:\\cfs"
    _shutdown
    return
  fi
  echo ""

  _run_cmd "C:\\cfs\\tests\\windows\\run_test.bat $winnt"
  if test $? -eq 0; then
    echo "Successfully run tests from: $vm."
    ((++passed))
  else
    echo "Errors in tests from: $vm."
    failed+=("$vm")
  fi
  echo ""

  _run_cmd "rmdir /S /Q C:\\cfs"
  _shutdown
}

function begin_tests {
  clear
  printf "[%s] \e[4;34m%s\x1b[0m Running tests...\n\n" "$(date +%H:%M:%S)" "${BASH_SOURCE[0]}"
  echo ""

  cd "$(dirname BASH_SOURCE[0])" || exit
  echo ""

  start=$(date +%s%3N)
}

function end_tests {
  end=$(date +%s%3N)

  printf "\x1b[32m[----------]\x1b[0m Global tests environments tear-down\n"
  printf "\x1b[32m[==========]\x1b[0m %s test environments ran. (%s ms total)\n" "$total" "$((end - start))"
  printf "\x1b[32m[  PASSED  ]\x1b[0m %s test environments\n" "$passed"

  if test ${#failed[@]} -ne 0; then
    printf "\x1b[31m[  FAILED  ]\x1b[0m %s test environments, listed below:\n" "${#failed[@]}"
    printf "\x1b[31m[  FAILED  ]\x1b[0m %s\n" "${failed[@]}"
    exit 1
  fi

  exit 0
}

begin_tests

run_linux_test debian_potato/i386    debian/eol:potato   linux/i386
run_linux_test debian_woody/i386     debian/eol:woody    linux/i386
run_linux_test debian_etch/i386      debian/eol:etch     linux/i386
run_linux_test debian_lenny/amd64    debian/eol:lenny    linux/amd64
run_linux_test debian_squeeze/amd64  debian/eol:squeeze  linux/amd64
run_linux_test debian_wheezy/amd64   debian/eol:wheezy   linux/amd64
run_linux_test debian_jessie/amd64   debian/eol:jessie   linux/amd64
run_linux_test debian_stretch/amd64  debian/eol:stretch  linux/amd64
run_linux_test debian_buster/amd64   debian/eol:buster   linux/amd64
run_linux_test debian_bullseye/amd64 debian/eol:bullseye linux/amd64
run_linux_test debian_bookworm/amd64 debian:bookworm     linux/amd64
run_linux_test debian_trixie/amd64   debian:trixie       linux/amd64

run_windows_test "Windows 2000 32-bit"  Administrator 1234 0x0500
run_windows_test "Windows XP 32-bit"    Administrator 1234 0x0501
run_windows_test "Windows Vista 32-bit" storto        1234 0x0600
run_windows_test "Windows 7 32-bit"     storto        1234 0x0601
run_windows_test "Windows 7 64-bit"     storto        1234 0x0601
run_windows_test "Windows 8 32-bit"     storto        1234 0x0602
run_windows_test "Windows 8 64-bit"     storto        1234 0x0602
run_windows_test "Windows 8.1 32-bit"   storto        1234 0x0603
run_windows_test "Windows 8.1 64-bit"   storto        1234 0x0603
run_windows_test "Windows 10 32-bit"    storto        1234 0x0A00
run_windows_test "Windows 10 64-bit"    storto        1234 0x0A00
run_windows_test "Windows 11 64-bit"    storto        1234 0x0A00

end_tests
