# Calibration: how you are scored

F-004 (calibrated estimate capture). This guide is for everyone who takes calibration exercises or answers estimate requests. The rules below are the ones the platform applies (`internal/estimate/score.go`).

## What calibration means

You are **calibrated** when your stated confidence matches how often you are right:

- your 90% ranges contain the true value about 90% of the time;
- when you say you are 70% sure of a true-or-false answer, you are right about 70% of the time.

Most people start **overconfident**: their ranges are too narrow, and they are right less often than they say. Practice and feedback fix this quickly.

## Exercises

An exercise is a set of questions with known answers (20 by default, set by your administrators):

- **Range questions.** Give a lowest and a highest value such that you are 90% sure the true value lies between them.
- **True-or-false questions.** Choose true or false, and say how sure you are, from 50% (a guess) to 100% (certain).

There is no time limit. You see the answers and their sources only after you submit. A question you answered is not asked again for a while (180 days by default).

### The equivalent bet

To check a range, imagine two ways to win a prize. You win if the true value is inside your range, or you win by spinning a wheel that pays out 90% of the time. If you would rather spin the wheel, your range is too narrow, so widen it. If you would rather bet on your range, it may be wider than you need. When you would not mind which, the range is right.

## Your score

Your score counts your answers from a recent window (the last year by default). Each kind of question is scored separately, and only once you have answered enough of that kind (20 by default). Until then it shows as **not yet measured**.

### Range questions

The platform counts how many of your ranges held the true value (the **hit rate**). Even a perfectly calibrated person will not hit exactly 90%, so your count is compared with a **tolerance band**. The band is the range a calibrated person would land in 90% of the time with the same number of answers:

| Answers | Calibrated if the ranges that held number |
|---:|---|
| 10 | 7 to 10 |
| 20 | 16 to 20 |
| 100 | 85 to 95 |

- **Below the band: overconfident.** Your ranges are too narrow.
- **Inside the band: calibrated.**
- **Above the band: underconfident.** Your ranges are wider than they need to be. This only shows with enough answers.

### True-or-false questions

The platform adds up your stated confidences: that is how many answers you expected to get right. It then compares that with how many you did get right, allowing for chance. The allowance is a z-test at the 90% level. The result reads:

- **overconfident**: noticeably fewer right than you expected;
- **calibrated**: within the allowance;
- **underconfident**: noticeably more right than you expected.

A **Brier score** is shown too: the average of (confidence − outcome)², where the outcome is 1 for right and 0 for wrong. Lower is better, and 0 is perfect.

### Your overall class

Your overall class is your range class when your ranges are measured, otherwise your true-or-false class, otherwise not yet measured. Range questions are the ones that matter most for risk estimates.

## How your score is used

- When you answer an estimate request, your class and hit rate at that moment are saved with the answer.
- An analyst may combine several answers with a **calibration-weighted** average. Your weight is:
  - 1 if you are calibrated;
  - 0.5 if you are not yet measured;
  - 1 − 2.5 × |hit rate − 0.9| if you are over- or underconfident, but never less than 0.1.

## Who sees what

- **You** see all your exercises, answers and score history.
- **Analysts** who send you requests see your current class and hit rate, and the score saved with each answer. They never see your exercises or answers.
- **Auditors** see scores and their history. Every view of someone else's record is recorded in the audit trail.

Exercises and score history are deleted after the retention period (3 years by default). The score saved with an answer stays with that answer, as part of the risk record.
