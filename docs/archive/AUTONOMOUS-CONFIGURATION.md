# Configuring Hermes (Opus) for Autonomous Work

**Your Question**: How can I configure you (Opus/Hermes) to work autonomously on hermes-aegis?

**Answer**: There are 3 main approaches, each with different trade-offs.

---

## Approach 1: Work Together → Pass Off via Cronjob (Recommended)

### The Pattern

**Phase 1 - Interactive (Now)**:
- We work together to complete Chunk 1 (Tasks 2-5)
- I learn the project structure, patterns, your preferences
- We verify everything works

**Phase 2 - Autonomous (Later)**:
- You schedule me to work on Chunk 2 overnight or when you're away
- I work independently, commit results
- You review when you're back

### How to Set It Up

1. **First, complete Chunk 1 together** (so I understand the codebase):

```
You: "Let's implement Task 2 - encrypted vault"
Me: [Uses subagent-driven-development to implement Task 2]
You: [Reviews, we iterate]
Me: [Commits when approved]
# Repeat for Tasks 3-5
```

2. **Then, schedule me for autonomous work**:

```bash
# Schedule me to work on Chunk 2 (Tasks 6-7)
schedule_cronjob(
    prompt="""Work on hermes-aegis project at /Users/evinova/Projects/hermes-aegis

GOAL: Implement Chunk 2 (Tasks 6-7) from docs/IMPLEMENTATION-PLAN.md

INSTRUCTIONS:
1. Read current git status to see completed work
2. Use subagent-driven-development skill to implement:
   - Task 6: Secret detection patterns
   - Task 7: Audit trail with hash chain
3. Follow strict TDD methodology from the plan
4. Commit after each task with suggested message
5. DO NOT git push (just commit locally)
6. When complete, provide summary of:
   - Tasks completed
   - Tests written
   - Commits made
   - Any issues encountered

PROJECT CONTEXT:
- Location: /Users/evinova/Projects/hermes-aegis
- Currently on Task 5 (just completed Chunk 1)
- Using Python 3.13, pytest for testing
- Git repo, commit messages follow conventional commits
""",
    schedule="6h",  # Run in 6 hours
    deliver="origin",  # Send results back to this chat
)
```

**When I complete**: You'll get a message with summary, you review, then schedule me for next chunk.

---

## Approach 2: Continuous Autonomous Sessions

### The Pattern

I work on the project in scheduled 2-hour blocks, picking up where I left off each time.

### Setup

```bash
# Schedule recurring autonomous work sessions
schedule_cronjob(
    prompt="""Continue work on hermes-aegis at /Users/evinova/Projects/hermes-aegis

GOAL: Implement next chunk from docs/IMPLEMENTATION-PLAN.md

INSTRUCTIONS:
1. Check docs/STATUS.md to see what's complete
2. Read git log to understand recent changes
3. Identify next incomplete chunk
4. Use subagent-driven-development to implement next 2-3 tasks
5. Update STATUS.md with progress
6. Commit work (do NOT push)
7. Report completion status

CONSTRAINTS:
- Work for max 2 hours (stop gracefully if incomplete)
- Commit frequently (after each task)
- If stuck >30 min on one task, document issue and move on
- DO NOT push to GitHub
""",
    schedule="every 4h",  # Run every 4 hours
    repeat=10,  # Stop after 10 iterations
    deliver="telegram",  # Or "origin" to send back here
)
```

**Pros**: Hands-off, I make steady progress  
**Cons**: Might work while you sleep (could be good or bad!)

---

## Approach 3: On-Demand Autonomous via delegate_task

### The Pattern

You trigger me manually when you want me to work on a specific chunk.

### How It Works

**In this chat session**, you just say:

```
"Implement Chunk 2 (Tasks 6-7) autonomously"
```

Then I do:

```python
delegate_task(
    goal="Implement Chunk 2 from hermes-aegis plan",
    context="""
    Full context from plan...
    """,
    toolsets=['terminal', 'file', 'web'],
    max_iterations=50
)
```

**Pros**: You control when I work  
**Cons**: Ties up this chat session, uses your tokens

---

## My Recommendation: Hybrid Approach

### Week 1: Work Together (Learn the Project)

**Days 1-2**: Build Chunk 1 together (Tasks 2-5)
- I use subagent-driven-development but you're here
- We iterate on issues together
- I learn your code style preferences
- We verify tests work

**Why together first?**
- I learn the project structure
- We verify the plan is actually executable  
- We catch any plan issues early
- I understand your quality bar

### Week 1 Evening: Autonomous Chunk 2

**Friday evening**: Schedule me to work on Chunk 2 overnight

```bash
schedule_cronjob(
    prompt="[Full detailed prompt with Chunk 2 tasks]",
    schedule="8h",  # While you sleep
    deliver="telegram"  # Wake up to results
)
```

**Saturday morning**: 
- You review my work
- We fix any issues together
- You approve or request changes

### Week 2: More Autonomous

**Once I've proven I can do Chunks 1-2 well**:
- Schedule me for Chunk 3, 4, 5 in sequence
- Check in daily to review progress
- I work while you do other things

---

## Configuration Options

### Set My Working Hours

```yaml
# In schedule_cronjob prompts, add:
CONSTRAINTS:
- Only work 9am-5pm Pacific (safety window)
- Stop work at 4:30pm to leave time for reporting
```

### Set Quality Thresholds

```yaml
# In prompts, specify:
QUALITY RULES:
- All tests must pass before committing
- Test coverage >80% for new code
- No TODOs or FIXME in committed code
- Follow existing code style (check other files for patterns)
```

### Set Communication Style

```yaml
# In prompts:
REPORTING:
- Commit message: conventional commits style
- Progress updates: every 30 minutes if working >1 hour
- Issues: report immediately, don't struggle silently >15 min
```

---

## What I Need to Work Autonomously

✅ **Already have**:
- Clear implementation plan (docs/IMPLEMENTATION-PLAN.md)
- Test methodology (TDD throughout)
- Commit message patterns
- Success criteria

⚠️ **Would help**:
- Your code style preferences (variable naming, comment style)
- Your quality bar (when is "good enough" vs "needs polish")
- Priority: speed vs quality (if time-constrained)

🚫 **Can't do autonomously** (requires you):
- Make breaking changes to architecture
- Push to GitHub
- Decide between alternative approaches without criteria
- Add features not in the plan

---

## Recommended First Step

**Let's do Chunk 1 TOGETHER now** using subagent-driven-development:

1. I'll use the skill to delegate Task 2 (encrypted vault)
2. You'll see how I orchestrate subagents
3. We'll verify it works well
4. Then you decide: continue together, or schedule me for autonomous work

**Command for me**:
```
"Use subagent-driven-development to implement Task 2 from the implementation plan"
```

I'll:
- Read Task 2 details
- Dispatch implementer subagent
- Dispatch spec reviewer
- Dispatch quality reviewer
- Update todo list
- Show you results

Then we iterate or move to Task 3.

**Want to try this now?** Or do you have other questions about autonomous configuration first? 🌙
