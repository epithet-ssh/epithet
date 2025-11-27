---
title: "Move AWS-specific code from epithet to epithet-aws"
id: 3ja74tqp
created: 2025-11-25T17:45:23Z
updated: 2025-11-25T17:50:01Z
priority: critical
tags: [task]
---

Move all AWS Lambda deployment code from the epithet repository to the epithet-aws repository. epithet-aws already contains most of the AWS-specific functionality; the main epithet repo has duplicate code that should be removed.