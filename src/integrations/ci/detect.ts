// ─── CI/CD Platform Detection ───
// Auto-detects the CI platform from environment variables

import type { CIEnvironment, CIPlatform } from "../../types.js";

export function detectCI(): CIEnvironment {
  // GitHub Actions
  if (process.env.GITHUB_ACTIONS === "true") {
    return {
      platform: "github-actions",
      buildId: process.env.GITHUB_RUN_ID,
      branch: process.env.GITHUB_HEAD_REF || process.env.GITHUB_REF_NAME,
      commitSha: process.env.GITHUB_SHA,
      prNumber: process.env.GITHUB_EVENT_NAME === "pull_request"
        ? parseInt(process.env.GITHUB_REF?.match(/refs\/pull\/(\d+)/)?.[1] || "0", 10) || undefined
        : undefined,
      repository: process.env.GITHUB_REPOSITORY,
      isCI: true,
    };
  }

  // GitLab CI
  if (process.env.GITLAB_CI === "true") {
    return {
      platform: "gitlab-ci",
      buildId: process.env.CI_PIPELINE_ID,
      branch: process.env.CI_COMMIT_BRANCH || process.env.CI_MERGE_REQUEST_SOURCE_BRANCH_NAME,
      commitSha: process.env.CI_COMMIT_SHA,
      prNumber: process.env.CI_MERGE_REQUEST_IID
        ? parseInt(process.env.CI_MERGE_REQUEST_IID, 10)
        : undefined,
      repository: process.env.CI_PROJECT_PATH,
      isCI: true,
    };
  }

  // Jenkins
  if (process.env.JENKINS_URL) {
    return {
      platform: "jenkins",
      buildId: process.env.BUILD_NUMBER,
      branch: process.env.BRANCH_NAME || process.env.GIT_BRANCH,
      commitSha: process.env.GIT_COMMIT,
      prNumber: process.env.CHANGE_ID ? parseInt(process.env.CHANGE_ID, 10) : undefined,
      repository: process.env.GIT_URL,
      isCI: true,
    };
  }

  // Azure DevOps
  if (process.env.TF_BUILD === "True") {
    return {
      platform: "azure-devops",
      buildId: process.env.BUILD_BUILDID,
      branch: process.env.BUILD_SOURCEBRANCH?.replace("refs/heads/", ""),
      commitSha: process.env.BUILD_SOURCEVERSION,
      prNumber: process.env.SYSTEM_PULLREQUEST_PULLREQUESTNUMBER
        ? parseInt(process.env.SYSTEM_PULLREQUEST_PULLREQUESTNUMBER, 10)
        : undefined,
      repository: process.env.BUILD_REPOSITORY_NAME,
      isCI: true,
    };
  }

  // CircleCI
  if (process.env.CIRCLECI === "true") {
    return {
      platform: "circleci",
      buildId: process.env.CIRCLE_BUILD_NUM,
      branch: process.env.CIRCLE_BRANCH,
      commitSha: process.env.CIRCLE_SHA1,
      prNumber: process.env.CIRCLE_PR_NUMBER
        ? parseInt(process.env.CIRCLE_PR_NUMBER, 10)
        : undefined,
      repository: `${process.env.CIRCLE_PROJECT_USERNAME}/${process.env.CIRCLE_PROJECT_REPONAME}`,
      isCI: true,
    };
  }

  // Generic CI detection
  if (
    process.env.CI === "true" ||
    process.env.CI === "1" ||
    process.env.CONTINUOUS_INTEGRATION === "true"
  ) {
    return {
      platform: "generic",
      branch: process.env.BRANCH || process.env.GIT_BRANCH,
      commitSha: process.env.COMMIT_SHA || process.env.GIT_COMMIT,
      isCI: true,
    };
  }

  // Not CI
  return {
    platform: "generic",
    isCI: false,
  };
}

export function getCIAnnotationFormat(platform: CIPlatform): "github" | "gitlab" | "generic" {
  switch (platform) {
    case "github-actions": return "github";
    case "gitlab-ci": return "gitlab";
    default: return "generic";
  }
}

export function emitCIAnnotation(
  platform: CIPlatform,
  level: "error" | "warning" | "notice",
  message: string,
  file?: string,
  line?: number
): void {
  switch (platform) {
    case "github-actions":
      // GitHub Actions workflow commands
      if (file) {
        console.log(`::${level} file=${file}${line ? `,line=${line}` : ""}::${message}`);
      } else {
        console.log(`::${level}::${message}`);
      }
      break;

    case "gitlab-ci":
      // GitLab uses ANSI colors
      const prefix = level === "error" ? "\x1b[31m" : level === "warning" ? "\x1b[33m" : "\x1b[36m";
      console.log(`${prefix}[${level.toUpperCase()}]\x1b[0m ${message}`);
      break;

    default:
      console.log(`[${level.toUpperCase()}] ${message}`);
  }
}

export function setCIOutput(platform: CIPlatform, key: string, value: string): void {
  switch (platform) {
    case "github-actions":
      // GitHub Actions GITHUB_OUTPUT file
      const outputFile = process.env.GITHUB_OUTPUT;
      if (outputFile) {
        const fs = require("fs");
        fs.appendFileSync(outputFile, `${key}=${value}\n`);
      }
      break;

    case "gitlab-ci":
      // GitLab uses dotenv artifacts
      console.log(`${key}=${value}`);
      break;

    default:
      console.log(`SCATO_${key.toUpperCase()}=${value}`);
  }
}
