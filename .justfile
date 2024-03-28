default:
  just --list

clippy:
  cargo clippy --all-targets -- -D warnings

check:
  cargo check --all-targets

test:
  cargo test --tests

##! Tag and push it. Example: ❯ make tag-and-push new_tag=v0.0.2
tag-and-push:
  git tag -a ${new_tag} && git push origin ${new_tag}

##! Generate new test coverage
coverage:
  ./generate_coverage.sh

open-coverage:
  open -a Google\ Chrome.app target/debug/coverage/index.html

coverage-and-open: coverage open-coverage

##! Generate docs
generate-docs:
  cargo doc --open --no-deps --package murray-rs