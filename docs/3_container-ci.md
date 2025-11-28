# Containerised CCC Readiness Pipeline

This guide packages the `make validate-ci` toolchain into a Docker image so the same
environment can be reused locally and in CI jobs.

## 1. Build the image

```bash
# From repo root
DOCKER_BUILDKIT=1 docker build -t ccc-readiness:latest .
```

The `Dockerfile` installs Terraform, Privateer, Prowler, Go, and the generated VPC
plugin. Update the build args if you need a different Privateer release:

```bash
DOCKER_BUILDKIT=1 docker build \
  --build-arg PRIVATEER_VERSION=v0.14.0 \
  -t ghcr.io/your-org/ccc-readiness:0.1.0 .
```

## 2. Run the validator in the container

Mount the working tree and point `make` at your CI posture (`.env.ci` ships with
replication toggles disabled so the baseline passes without extra IAM/KMS setup).

```bash
docker run --rm \
  -v "$(pwd)":/workspace \
  -w /workspace \
  --env-file .env.ci \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  ccc-readiness:latest \
  make validate-ci ENV_FILE=.env.ci
```

Pass whichever AWS credentials or LocalStack endpoints you use. Without runtime
access, set `ENABLE_VPC_FLOW_LOGS=false` in the env file to skip the flow-log
runtime guard.

## 3. Push to a registry

```bash
# Example for GHCR
docker tag ccc-readiness:latest ghcr.io/your-org/ccc-readiness:0.1.0
docker push ghcr.io/your-org/ccc-readiness:0.1.0
```

Repeat for each registry you need (ECR, GitLab Registry, etc.).

## 4. Use the image in CI pipelines

### GitHub Actions

Swap the tool-install steps with a container run:

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Pull container
        run: docker pull ghcr.io/your-org/ccc-readiness:0.1.0
      - name: Run make validate-ci
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_SESSION_TOKEN: ${{ secrets.AWS_SESSION_TOKEN }}
        run: |
          docker run --rm \
            -v "$PWD":/workspace \
            -w /workspace \
            --env-file .env.ci \
            -e AWS_ACCESS_KEY_ID \
            -e AWS_SECRET_ACCESS_KEY \
            -e AWS_SESSION_TOKEN \
            ghcr.io/your-org/ccc-readiness:0.1.0 \
            make validate-ci ENV_FILE=.env.ci
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ccc-validate-artifacts
          path: |
            output/ci/*
            output/ccc-vpc/ccc-vpc.json
            output/runtime/runtime-guard.json
            output/validate/*.log
```

### GitLab CI

```yaml
validate_demo:
  image: docker:24
  stage: validate
  services:
    - docker:24-dind
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  before_script:
    - docker pull registry.gitlab.com/your-org/ccc-readiness:0.1.0
  script:
    - docker run --rm \
        -v "$CI_PROJECT_DIR":/workspace \
        -w /workspace \
        --env-file .env.ci \
        -e AWS_ACCESS_KEY_ID \
        -e AWS_SECRET_ACCESS_KEY \
        -e AWS_SESSION_TOKEN \
        registry.gitlab.com/your-org/ccc-readiness:0.1.0 \
        make validate-ci ENV_FILE=.env.ci
  artifacts:
    when: always
    paths:
      - output/ci/
      - output/validate/
      - output/ccc-vpc/ccc-vpc.json
      - output/runtime/runtime-guard.json
```

Re-use the existing `deploy_demo` job to run Terraform `apply` in the same image
or keep the two-stage approach (deploy → validate) and share artifacts/state.

## 5. Keeping the image up to date

- Rebuild when Terraform/Privateer/Prowler versions change.
- Tag releases (`0.1.0`, `0.1.1`) so pipelines can pin predictably.
- Consider an automated rebuild (e.g., nightly GitHub Action) to apply security
  patches to the base image.

With the container in place, developers and CI both run the exact same
`make validate-ci` command, eliminating tool mismatch while preserving the strict
CI gating behaviour.
