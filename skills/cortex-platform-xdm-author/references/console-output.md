<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Console output: mark the stages, and STOP loudly

This page is IDENTICAL in every instrument bundle in this project and is copied, never imported,
because a skill is installed on its own and a shared import path does not exist at runtime. It is
COMPLETE as it stands: everything needed to print any banner here is on this page, and nothing on
it requires another bundle to be installed. When the bundles are checked out together, a test
refuses drift between the copies.

COPY these, do not type them. A banner rendered from memory loses the squirrel first, then the
rules, then the named sections, and a four-line block with `?` down the left edge is not a banner.
Tests pin the templates, so what you copy is correct; whether you copied it is on you.

Write the banner as text in your REPLY, inside a fenced code block. Do NOT echo it from a
shell. Two reasons, and the second is the one that matters: a shell script is not cross platform,
and command output goes to TOOL RESULTS, which are not reliably shown to the user. A banner printed
by `echo` can be invisible in the one place it is meant to be seen.

Read this page AT the boundary, and print the banner as the FIRST thing in the reply that enters
the stage. If you are reading it ahead of time you are not in that stage yet and the banner is
not yet due; by the time you are, this line is far behind you and the moment to announce has gone.

## Three banners, and only three

| Banner | Fill | Squirrel | Means |
| --- | --- | --- | --- |
| STAGE | `#` | yes | The work moved on. Nothing is wanted from you. Keep reading or do not. |
| ACTION REQUIRED | `!` | yes | You must DO something this skill cannot. The run is stopped. |
| KEY DECISION / FEEDBACK NEEDED | `?` | yes | You must ANSWER something it cannot know. The run is stopped. |

The fills differ so the three are told apart from across the room, before a single word is read:
`#` is dense and even, `!` is a wall of vertical strokes, `?` is visibly ragged.

The squirrel appears on ALL THREE. It is the mark of the method, so anyone glancing at the
screen knows whose run this is without reading a word. What distinguishes a stop from a stage
change is the FILL and the headline beside the squirrel, not its presence.

STAGE is what a standalone skill announces where the harness announces a PHASE. The art is the
same and only the headline word differs, because the boundary being marked is this skill's own
workflow rather than the harness's sequence. When this skill is invoked BY the harness, the harness
announces its phases and this skill announces its stages inside them; the two do not compete.

The right edge is deliberately left open, so a long stage name cannot knock the box out of
alignment. Copy the rules exactly; they are 80 characters.

## 1. STAGE, on entering every stage of this skill's own workflow

```
################################################################################
################################################################################
########
########            )" .
########           /    \      (\-./
########          /     |    _/ o. \
########         |      | .-"      y)-   STAGE 2 - PROFILE THE SAMPLE
########         |      |/       _/ \
########         \     /j   _".\(@)
########          \   ( |    `.''  )
########           \  _`-     |   /
########             "  `-._  <_ (
########                    `-.,),)
########
################################################################################
################################################################################
```

## 2. ACTION REQUIRED, when the caller must DO something

Use it when the next step needs hands this skill does not have: a credential to paste, a console
check, a file only they can produce. It carries the COMPLETE instruction, field by field. The
caller should never have to work out what to do, and never have to scroll back to find it.

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!
!!!!            )" .
!!!!           /    \      (\-./
!!!!          /     |    _/ o. \
!!!!         |      | .-"      y)-   >>>  ACTION REQUIRED BY YOU  <<<
!!!!         |      |/       _/ \    WORK IS PAUSED UNTIL THIS IS DONE
!!!!         \     /j   _".\(@)
!!!!          \   ( |    `.''  )
!!!!           \  _`-     |   /
!!!!             "  `-._  <_ (
!!!!                    `-.,),)
!!!!
!!!!   ADD THE API KEY TO THE INTEGRATION INSTANCE
!!!!
!!!!   Cortex Platform > Settings > Data Sources > Add Instance
!!!!
!!!!   Integration:   <exact display name from the integration yml>
!!!!   Instance name: <what to call it>
!!!!   <Param 1>:     <what to enter>
!!!!   API token:     paste into the Password field
!!!!   Fetch events:  ON          Interval: <n> minutes
!!!!
!!!!   Click Test, then tell me when it passes.
!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

## 3. KEY DECISION, when the caller must ANSWER something

Use it when two readings lead to materially different work and the thing that settles it is
knowledge only the caller has: their estate, their policy, their appetite for a false positive.

```
????????????????????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????????????????????
????
????            )" .
????           /    \      (\-./
????          /     |    _/ o. \
????         |      | .-"      y)-   >>>  KEY DECISION - I NEED YOUR ANSWER  <<<
????         |      |/       _/ \    WORK IS PAUSED UNTIL YOU REPLY
????         \     /j   _".\(@)
????          \   ( |    `.''  )
????           \  _`-     |   /
????             "  `-._  <_ (
????                    `-.,),)
????
????   <five words naming the decision>
????
????   THE QUESTION
????     <one sentence, in plain words, no jargon>
????
????   OPTION A   <what it is>
????              If we go this way: <what changes downstream>
????
????   OPTION B   <what it is>
????              If we go this way: <what changes downstream>
????
????   MY RECOMMENDATION: <A or B>, because <one line>
????
????   WHY I CANNOT DECIDE THIS MYSELF
????     <the thing only you know: your estate, your policy, your risk>
????
????   Meanwhile I have carried on with: <what is not blocked>
????
????????????????????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????????????????????
```

## 3b. FEEDBACK NEEDED, the same banner with a different heading

Same `?` fill, same squirrel. Use it when nothing is strictly blocked but a number, a threshold or
a distribution should be seen by someone who knows the estate before it is built on.

```
????????????????????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????????????????????
????
????            )" .
????           /    \      (\-./
????          /     |    _/ o. \
????         |      | .-"      y)-   >>>  FEEDBACK NEEDED - PLEASE READ  <<<
????         |      |/       _/ \    WORK IS PAUSED UNTIL YOU REPLY
????         \     /j   _".\(@)
????          \   ( |    `.''  )
????           \  _`-     |   /
????             "  `-._  <_ (
????                    `-.,),)
????
????   <five words naming what you are judging>
????
????   WHAT I BUILT
????     <one sentence>
????
????   WHAT I WANT YOU TO LOOK AT
????     <the specific thing, and what a wrong answer would look like>
????
????     <name>   <value>   <what it means>
????     <name>   <value>   <what it means>
????
????   MY READING: <what you believe, in one line>
????
????   Tell me if that matches your estate, and I will continue.
????
????????????????????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????????????????????
```

## Rules for the two STOP banners

- NEVER ask the caller a question outside one of these banners. If a reply contains a question
  mark aimed at them and no `?` banner, that is a defect in the reply. The recorded failure is not
  someone missing a loud banner, it is a run sitting idle because the question was a sentence in a
  paragraph.
- The banner is the LAST thing in the reply. Nothing after it, no closing summary, no "let me
  know". Anything printed below it pushes it up the screen and defeats it.
- One banner per reply. Two questions in one reply means the second gets half an answer. If two
  decisions are genuinely open, put them as OPTION sets inside ONE banner.
- Always carry a recommendation. A decision banner without one hands the caller an unpriced
  choice and is just work passed back up. State which way you would go and why, in one line, so the
  reply can be a single word.
- Say what is NOT blocked. Do every part that does not depend on the answer first, then name
  what you did on the last line. A banner that stops everything when only one branch was blocked
  wastes the wait.
- NEVER print a credential into a banner. It says WHERE to paste a key; it never echoes one.
  A banner is high-visibility output that gets copied into notes and tickets, which is exactly the
  wrong place for a secret.
- After printing a STOP banner, STOP. Do not continue and do not poll.

## The test, before you print anything that is not a stage banner

Ask: is the run about to sit still? If yes, it gets a squirrel, and the only question left is which
one, `!` for a pair of hands or `?` for an answer. If no, it is not a banner, it is prose, and it
must not be dressed up as one. Banners spent on things that are not stops are how a stop stops
being noticed.
