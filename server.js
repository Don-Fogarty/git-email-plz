const express = require("express");
const crypto = require("crypto");
const app = express();

app.use(express.urlencoded({ extended: true, verify: (req, _res, buf) => { req.rawBody = buf.toString(); } }));
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ─── Health check ──────────────────────────────────────────────────

app.get("/", (_req, res) => {
  res.send("GitHub Email Bot is running.");
});

// ─── Slack slash command handler ───────────────────────────────────

app.post("/slack/command", async (req, res) => {
  // Verify Slack signature
  if (process.env.SLACK_SIGNING_SECRET) {
    const timestamp = req.headers["x-slack-request-timestamp"];
    const slackSig = req.headers["x-slack-signature"];
    if (!timestamp || !slackSig) return res.status(401).send("Missing signature");

    const fiveMin = 300;
    if (Math.abs(Math.floor(Date.now() / 1000) - parseInt(timestamp)) > fiveMin) {
      return res.status(401).send("Request too old");
    }

    const sigBase = `v0:${timestamp}:${req.rawBody}`;
    const myHash = "v0=" + crypto.createHmac("sha256", process.env.SLACK_SIGNING_SECRET)
      .update(sigBase).digest("hex");

    if (myHash !== slackSig) return res.status(401).send("Invalid signature");
  }

  const username = (req.body.text || "").trim();
  const responseUrl = req.body.response_url;

  if (!username) {
    return res.json({
      response_type: "ephemeral",
      text: "Usage: `/github-email <username>`\nExample: `/github-email torvalds`",
    });
  }

  if (!/^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$/.test(username)) {
    return res.json({
      response_type: "ephemeral",
      text: `\`${username}\` doesn't look like a valid GitHub username.`,
    });
  }

  // Respond to Slack immediately (must reply within 3s)
  res.json({
    response_type: "ephemeral",
    text: `:mag: Looking up email for *${username}*…`,
  });

  // Do the lookup in the background and post back
  lookupAndRespond(username, responseUrl).catch(console.error);
});

// ─── Core lookup logic ─────────────────────────────────────────────

async function lookupAndRespond(username, responseUrl) {
  try {
    const result = await findEmail(username);

    let slackMessage;
    if (result.emails.length > 0) {
      const emailList = result.emails
        .map((e) => `• \`${e.email}\`${e.source ? ` _(${e.source})_` : ""}`)
        .join("\n");

      slackMessage = {
        response_type: "in_channel",
        blocks: [
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `:white_check_mark: *<https://github.com/${username}|${result.name || username}>*\n${emailList}`,
            },
            ...(result.avatar
              ? {
                  accessory: {
                    type: "image",
                    image_url: result.avatar,
                    alt_text: username,
                  },
                }
              : {}),
          },
        ],
      };
    } else {
      slackMessage = {
        response_type: "ephemeral",
        text: `:x: No email found for *<https://github.com/${username}|${username}>*. They may have no public commits or use GitHub's noreply address exclusively.`,
      };
    }

    await fetch(responseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(slackMessage),
    });
  } catch (err) {
    console.error("Lookup error:", err);
    await fetch(responseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        response_type: "ephemeral",
        text: `:warning: Error looking up *${username}*: ${err.message}`,
      }),
    });
  }
}

async function findEmail(username) {
  const headers = {
    "User-Agent": "github-email-bot",
    Accept: "application/vnd.github.v3+json",
  };
  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `token ${process.env.GITHUB_TOKEN}`;
  }

  const emailSet = new Map();
  let name = null;
  let avatar = null;

  // ── Step 1: Check profile ──
  const profileRes = await fetch(`https://api.github.com/users/${username}`, { headers });
  if (profileRes.status === 404) throw new Error("User not found on GitHub.");
  if (!profileRes.ok) throw new Error(`GitHub API error: ${profileRes.status}`);

  const profile = await profileRes.json();
  name = profile.name;
  avatar = profile.avatar_url;
  if (profile.email) addEmail(emailSet, profile.email, "profile");

  // ── Step 2: Check public events ──
  const eventsRes = await fetch(
    `https://api.github.com/users/${username}/events/public?per_page=100`,
    { headers }
  );
  if (eventsRes.ok) {
    const events = await eventsRes.json();
    for (const event of events) {
      if (event.type === "PushEvent" && event.payload?.commits) {
        for (const commit of event.payload.commits) {
          if (commit.author?.email) {
            addEmail(emailSet, commit.author.email, "recent commit");
          }
        }
      }
    }
  }

  // ── Step 3: GitHub commit search API (searches ALL public repos, sorted oldest first) ──
  // Oldest commits are most likely to predate email privacy settings
  const searchHeaders = { ...headers, Accept: "application/vnd.github.cloak-preview+json" };
  for (const order of ["asc", "desc"]) {
    const searchRes = await fetch(
      `https://api.github.com/search/commits?q=author:${username}&sort=author-date&order=${order}&per_page=20`,
      { headers: searchHeaders }
    );
    if (searchRes.ok) {
      const searchData = await searchRes.json();
      for (const item of searchData.items || []) {
        // Check the commit author email from the API response
        if (item.commit?.author?.email) {
          addEmail(emailSet, item.commit.author.email, order === "asc" ? "early commit" : "recent commit");
        }
        if (item.commit?.committer?.email) {
          addEmail(emailSet, item.commit.committer.email, order === "asc" ? "early commit" : "recent commit");
        }
      }
    }
    // If we found emails from the oldest commits, no need to check newest too
    if (emailSet.size > 0 && order === "asc") break;
  }

  if (emailSet.size > 0) {
    return { emails: mapToArray(emailSet), name, avatar };
  }

  // ── Step 4: Deep .patch scan across repos (including forks, multiple commits per repo) ──
  // Fetch up to 30 repos, including forks this time
  const reposRes = await fetch(
    `https://api.github.com/users/${username}/repos?sort=pushed&per_page=30`,
    { headers }
  );
  if (reposRes.ok) {
    const repos = await reposRes.json();

    for (const repo of repos) {
      // Get up to 20 commits per repo, sorted oldest first to find pre-privacy emails
      const commitsRes = await fetch(
        `https://api.github.com/repos/${repo.full_name}/commits?author=${username}&per_page=20`,
        { headers }
      );
      if (!commitsRes.ok) continue;

      const commits = await commitsRes.json();
      if (commits.length === 0) continue;

      // Check commits from oldest to newest (reverse the array)
      const orderedCommits = [...commits].reverse();

      for (const commit of orderedCommits) {
        // First try the API commit data directly
        if (commit.commit?.author?.email) {
          addEmail(emailSet, commit.commit.author.email, `patch: ${repo.name}`);
        }
        if (commit.commit?.committer?.email) {
          addEmail(emailSet, commit.commit.committer.email, `patch: ${repo.name}`);
        }

        // If API data was noreply, try the .patch method on this commit
        if (emailSet.size === 0) {
          const patchRes = await fetch(
            `https://github.com/${repo.full_name}/commit/${commit.sha}.patch`,
            { headers: { "User-Agent": "github-email-bot" }, redirect: "follow" }
          );
          if (patchRes.ok) {
            const patchText = await patchRes.text();
            const fromMatch = patchText.match(/^From:.*<(.+?)>/m);
            if (fromMatch) addEmail(emailSet, fromMatch[1], `patch: ${repo.name}`);
          }
        }

        if (emailSet.size > 0) break; // found one in this repo
      }

      if (emailSet.size > 0) break; // found one, stop scanning repos
    }
  }

  return { emails: mapToArray(emailSet), name, avatar };
}

function addEmail(map, email, source) {
  if (!email) return;
  const lower = email.toLowerCase().trim();
  if (lower.includes("noreply.github.com")) return;
  if (lower === "none" || lower === "") return;
  if (!map.has(lower)) map.set(lower, source);
}

function mapToArray(map) {
  return [...map.entries()].map(([email, source]) => ({ email, source }));
}

// ─── Start server ──────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`GitHub Email Bot listening on port ${PORT}`);
});
