"use strict";

/**
 * Remove only the exact merged PR branch tip. A branch that has received new
 * commits, has an open PR, or cannot be verified must never be deleted.
 * GitHub does not offer conditional deleteRef; verify immediately before
 * deletion and fail closed if the ref has changed.
 */
module.exports = async function cleanupMergedBranches({ github, context, core }) {
  const { owner, repo } = context.repo;
  const defaultBranch = context.payload.repository.default_branch;
  const repoName = owner + "/" + repo;
  // Any failure to list open PRs aborts cleanup rather than guessing safety.
  const openPulls = await github.paginate(github.rest.pulls.list, {
    owner, repo, state: "open", per_page: 100,
  });
  const protectedHeads = new Set(
    openPulls
      .filter((pr) => pr.head.repo?.full_name === repoName)
      .map((pr) => pr.head.ref)
  );
  const closedPulls = await github.paginate(github.rest.pulls.list, {
    owner, repo, state: "closed", per_page: 100,
  });
  const handled = new Set();

  for (const pr of closedPulls) {
    if (!pr.merged_at || pr.head.repo?.full_name !== repoName) continue;
    const name = pr.head.ref;
    const expected = pr.head.sha;
    if (!name || name === defaultBranch || protectedHeads.has(name) ||
        handled.has(name) || !/^[0-9a-f]{40}$/i.test(expected ?? "")) continue;

    const ref = "heads/" + name;
    let current;
    try {
      current = await github.rest.git.getRef({ owner, repo, ref });
    } catch (error) {
      if (error.status === 404 || error.status === 422) {
        handled.add(name);
        continue;
      }
      throw error;
    }
    // SHA comparison prevents deleting a branch reused or advanced after merge.
    if (current.data?.object?.sha !== expected) {
      core.info("Skipping modified or reused branch: " + name);
      continue;
    }

    try {
      await github.rest.git.deleteRef({ owner, repo, ref });
      core.info("Deleted unchanged merged branch: " + name);
    } catch (error) {
      if (error.status !== 404 && error.status !== 422) throw error;
      core.info("Branch absent or protected: " + name);
    }
    handled.add(name);
  }
};
