start=0
end=0
passed=0
total=0
failed=()

function run_test {
  ((++total))

  if docker image inspect "$1" > /dev/null 2>&1; then
    docker image rm $1 -f
    echo ""
  fi

  docker build -f $2/Dockerfile .. --tag $1 --build-arg BASE_IMAGE=$3 --platform=$4
  echo ""

  echo "Running tests from: $1..."
  docker run --rm -it $1
  result=$?
  echo ""

  if [ $result -eq 0 ]; then
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

  if [ ${#failed[@]} ]; then
    printf "\x1b[31m[  FAILED  ]\x1b[0m %s test environments, listed below:\n" "${#failed[@]}"
    printf "\x1b[31m[  FAILED  ]\x1b[0m %s\n" "${failed[@]}"
    exit 1
  fi

  exit 0
}

begin_tests

run_test debian_woody/i386    linux debian/eol:woody   linux/i386
run_test debian_etch/i386     linux debian/eol:etch    linux/i386
run_test debian_etch/amd64    linux debian/eol:etch    linux/amd64
run_test debian_lenny/amd64   linux debian/eol:lenny   linux/amd64
run_test debian_squeeze/amd64 linux debian/eol:squeeze linux/amd64

end_tests
