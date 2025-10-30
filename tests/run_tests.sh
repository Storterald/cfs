start=0
end=0
passed=0
total=0
failed=()

function run_linux_test {
  ((++total))

  if docker image inspect "$1" > /dev/null 2>&1; then
    docker image rm $1 -f
    echo ""
  fi

  docker build -f linux/Dockerfile .. --tag $1 --platform=$3 --build-arg BASE_IMAGE=$2
  if test $? -ne 0; then
    echo "Errors in tests from: $1. Could not build docker image."
    failed+=("$1")
  fi
  echo ""

  echo "Running tests from: $1..."
  docker run --rm -it $1
  result=$?
  echo ""

  if test $result -eq 0; then
    echo "Successfully run tests from: $1."
    ((++passed))
  else
    echo "Errors in tests from: $1."
    failed+=("$1")
  fi
  echo ""

  docker image rm $1 -f
  echo ""
}

function run_windows_test {
  cfs_dir="$(dirname "$(dirname "$(readlink -fm "$0")")")"
  shared=CFSTestShare

  function _run_cmd {
    VBoxManage guestcontrol "$1" run          \
      --exe "C:\\Windows\\System32\\cmd.exe"  \
      --username Administrator                \
      --password 1234                         \
      --wait-stdout                           \
      --wait-stderr                           \
      --timeout 30000                         \
      -- /c "$2"
  }

  function _clear {
    _run_cmd "$1" "net use X: /delete"
    VBoxManage sharedfolder remove "$1" \
      --name $shared                    \
      --transient
    VBoxManage controlvm "$1" acpipowerbutton
  }

  VBoxManage startvm "$1"
  if test $? -ne 0; then
    echo "Errors in tests from: $1. Could not start vm."
    failed+=("$1")
    return
  fi

  VBoxManage guestproperty wait "$1" "/VirtualBox/GuestAdd/Revision" \
      --timeout 60000

  VBoxManage sharedfolder add "$1"  \
    --name $shared                  \
    --hostpath "$cfs_dir"           \
    --transient                     \
    --automount
  if test $? -ne 0; then
    echo "Errors in tests from: $1. Could not add shared folder."
    failed+=("$1")
    VBoxManage controlvm "$1" acpipowerbutton
    return
  fi

  _run_cmd "$1" "net use X: \\\\vboxsvr\\CFSTestShare"
  if test $? -ne 0; then
    echo "Errors in tests from: $1. Could not alias shared folder."
    failed+=("$1")
    _clear "$1"
    return
  fi

  sleep 10  # TODO: reliable wait for complete boot

  _run_cmd "$1" "X:\\tests\\windows\\run_test.bat"
  if test $? -eq 0; then
    echo "Successfully run tests from: $1."
    ((++passed))
  else
    echo "Errors in tests from: $1."
    failed+=("$1")
  fi
  echo ""

  _clear "$1"
}

function begin_tests {
  clear
  printf "[%s] \e[4;34m%s\x1b[0m Running tests...\n\n" "$(date +%H:%M:%S)" "${BASH_SOURCE[0]}"
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

run_windows_test "Windows XP 32-bit"

end_tests
