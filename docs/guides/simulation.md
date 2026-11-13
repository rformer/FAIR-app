# Simulation: how the platform computes risk

F-005 (Monte Carlo simulation engine). This guide is for risk analysts and for everyone who reads simulation results. It describes what the engine does with a scenario, what the results mean, and what each warning says. The rules are the ones the engine applies (`engine/fairsim`, engine version 0.1.0).

## What a run is

A run simulates one **version** of a scenario many times. Each simulated year is called an **iteration**. You choose:

- **Control sets.** The current set is always simulated. You can add the scenario's other sets to compare them.
- **Iterations.** The number of simulated years. If you leave it empty, the installation's default applies (100,000 unless your administrators changed it). More iterations give steadier results and take longer.
- **Seed.** A whole number that fixes the random numbers. If you leave it empty, a random seed is chosen. The run records its seed either way, so it can be reproduced.

The engine reads the scenario version exactly as it was saved, with the library and control versions it pins (its **input bundle**). Saving a new version or adopting newer library entries never changes a run that already exists.

**Every input is sampled independently.** The engine does not model correlations between inputs, for example between how often an event happens and how much it costs. Every result says so.

## How each estimate is sampled

Every estimate has a minimum, a most likely value, a maximum and a confidence, for example "2 to 12, most likely 6, at 90% confidence". The engine turns it into a **Beta-PERT distribution** that:

- has its peak at the most likely value, and
- puts exactly your stated confidence between your minimum and maximum: for 90% confidence, 5% of draws fall below the minimum and 5% above the maximum.

So a 90% estimate is honoured as a 90% range. The distribution's true bounds lie beyond your minimum and maximum, but never outside what the unit allows:

| Unit | Allowed values |
|---|---|
| Events per year, amounts | 0 or more |
| Probabilities, fractions | 0 to 1 |
| Percentiles (threat capability, resistance strength) | 0 to 100 |

### Fallbacks

Sometimes no such distribution exists. For example, "0 to 4 events" cannot put 5% of draws below 0. The engine then uses a fallback and records it on the run as a warning, with the estimate's place in the scenario:

| Code | When | What the engine does |
|---|---|---|
| `point` | The minimum equals the maximum | The quantity is that constant value. |
| `domain_low` | The distribution would need values below what the unit allows | The lower bound is set at the unit's limit, for example 0. The upper bound is chosen so that your range still holds your confidence in total; the two tails are no longer equal. |
| `domain_high` | The distribution would need values above what the unit allows | As `domain_low`, at the upper limit (1 for a probability, 100 for a percentile). |
| `bounds` | No distribution within the unit's limits holds your confidence, for example a wide 50% range of a probability | A plain Beta-PERT from your minimum to your maximum: your range is treated as certain. Consider a narrower range or a higher confidence. |

`domain_low` is common and harmless: it appears whenever an estimate starts at or near zero.

## A simulated year

For each iteration and each control set, the engine computes one year.

1. **Year-level values.** It draws every frequency and probability the scenario uses once for the year: contact frequency, probability of action, threat event frequency, Vulnerability, resistance strength, loss event frequency (whichever the scenario enters), each secondary stakeholder group's secondary loss event frequency (SLEF), and each control effect.
2. **Controls.** See [Controls](#controls).
3. **Vulnerability.** If the scenario enters Vulnerability, that value is used. If Vulnerability is derived, it is the probability that a threat agent's capability exceeds the year's resistance strength: Vulnerability = 1 − F(resistance strength), where F is the threat capability estimate's cumulative distribution. Threat capability itself is not drawn per year; its whole distribution is used.
4. **Frequencies.** Threat event frequency = contact frequency × probability of action (or as entered); loss event frequency = threat event frequency × Vulnerability (or as entered).
5. **Loss events.** The number of loss events in the year is drawn from a Poisson distribution with the year's loss event frequency.
6. **Primary loss.** For each loss event, each form of primary loss the scenario has (productivity, response, replacement, fines and judgments, competitive advantage, reputation) is drawn from its estimate.
7. **Secondary loss.** For each loss event and each stakeholder group, a secondary loss event happens with probability SLEF. When it does, each of the group's forms of loss is drawn.
8. **Annualized loss.** The year's total of primary and secondary loss.

**Very frequent events.** For each year, the first 1,000 loss events are drawn one by one. The total of any further events is drawn from a normal distribution with the right mean and variance (warning `large_frequency`). This keeps very frequent scenarios fast, and it is accurate at such counts.

## Controls

A scenario's estimates describe the **current** state, with the current control set in place. Another control set is simulated by comparison with it:

- **Added** controls are in the set but not in the current one.
- **Removed** controls are in the current set but not in this one.

Each control has effects. A control set may override a control's effect for this scenario. Controls apply as follows:

- **Reductions** of contact frequency, probability of action, threat capability or a form of loss. An added control multiplies the factor by (1 − reduction). A removed control divides it by (1 − reduction). Several reductions of one factor multiply.
  - A removed reduction above 99.9% is capped at 99.9%, so the division stays finite (warning `reduction_capped`).
  - A probability of action pushed above 1 by a removal is clipped to 1 (warning `probability_clipped`).
  - When the scenario enters threat event frequency or loss event frequency directly, reductions of contact frequency and probability of action apply to the frequency it enters. The product is the same.
  - A reduction of a form of loss applies to that form in primary and in secondary loss.
- **Resistance strength.** A set's resistance strength is the stronger of the entered estimate and the added controls' strengths.
  - Removing a control that provides resistance strength is not modelled, because the entered estimate already includes it (warning `resistance_removal_not_modelled`).
- **Effects with nothing to apply to.** Threat capability and resistance strength effects need derived Vulnerability. When Vulnerability is entered directly they are not modelled (warning `effect_not_modelled`).
- **Changed effects.** A control may be in both the current set and another set, but with a different effect (another version, or an override). The current effect is then removed and the set's effect added (warning `control_effect_changed`).

**Common random numbers.** Every control set uses the same random numbers for the same quantity in the same year. Differences between sets therefore come from the controls, not from sampling noise. A set identical to the current one gives exactly the same losses every year.

## Results

For each control set, from all simulated years:

- **Annualized loss.**
  - Mean and standard deviation.
  - Minimum and maximum.
  - Percentiles 1, 5, 10, 25, 50 (the median year), 75, 90 (a 1-in-10 year), 95 (1 in 20) and 99 (1 in 100). Each percentile is an actual simulated year's loss, never interpolated.
  - The chance of any loss in a year.
- **Loss event frequency**: the same summaries of the year's rate.
- **Loss per event**: the same summaries over individual loss events.
  - When a run has more than 2,000,000 events in one control set, the engine summarizes the first events of every year, as many as fit (warning `loss_per_event_sampled`).
  - Events of a year are alike, so this sample is unbiased.
- **Loss exceedance curve**: the chance that a year's loss exceeds each of 200 amounts, from small losses up to the largest simulated year.
- **Breakdown**: mean annualized loss split into primary and secondary, by form of loss and by stakeholder group.
- **Comparison** (other control sets): the difference from the current set in mean and in percentiles 50, 90, 95 and 99. It also gives the summary of the year-by-year difference, which common random numbers make meaningful.

### Convergence

A run's results carry sampling error, which shrinks as iterations grow. For each control set the engine reports:

- the **standard error** of the mean, and the **relative standard error** (standard error ÷ mean);
- **95% intervals** for percentiles 50, 90, 95 and 99. They are distribution-free: the true percentile lies in the interval at least 95% of the time.

When the relative standard error is above the installation's threshold (1% by default), the run is flagged `not_converged`. Run it again with more iterations before relying on the tails.

### Sensitivity

For each input of a control set, meaning each estimate the scenario uses and each control effect the set adds or removes, the engine reports:

- **Swing.** It holds the input at its 5th and then at its 95th percentile, with everything else sampled as before, and reports the mean annualized loss each time. This uses the first 20,000 iterations. The inputs with the largest difference between the two matter most.
- **Rank correlation.** The Spearman correlation between the input's value in each year and the year's loss. For a form of loss, the input's value is the year's total of that form.
  - Threat capability has no yearly value, so it has no correlation.
  - Neither does an input that never varies.

Holding threat capability at a percentile means one fixed capability against each year's resistance strength. That year's Vulnerability is then 0 or 1, so threat capability's swing is often large.

## Aggregates

An aggregate combines runs of several scenarios into one annualized loss for a business unit.

- **Members.** Each member is one control set of a succeeded run. Members must be inside the aggregate's business unit and have the same number of iterations.
- **Independence.** Members are combined as independent. Each member's years are shuffled by the aggregate's seed before they are added, so members never share random numbers, even if their runs used the same seed. Correlations between scenarios are not modelled; the aggregate says so.
- **Contributions.** For each member: its mean, and its share of the aggregate's 1-in-20 year.
- **Engine versions.** When members were computed by different engine versions, the aggregate shows it.
- **Visibility.** An aggregate is visible only to someone who can see every member run.

## Reproducibility

A run's results are identical, bit for bit, for the same input bundle, seed, iterations and control sets on the same engine version and CPU architecture. This holds whatever the CPU model, the number of workers and the order runs are executed in.

Every run records:

- its input bundle's digest;
- the engine version and CPU architecture;
- the engine's validation record;
- a **results digest** over its inputs, the engine and every result.

**Reproduce** a run to check it. The new run uses the same inputs and is compared when it succeeds:

| Outcome | Meaning |
|---|---|
| `match` | Same engine version and architecture, identical results. |
| `mismatch` | Same engine version and architecture, different results. This should never happen; report it. |
| `other_version` | Computed by another engine version, so results may differ legitimately. |
| `other_architecture` | Computed on another CPU architecture (amd64 or arm64), so results may differ in the last digits. |

A reproduction is refused if the scenario version's input bundle no longer has the recorded digest. This cannot happen while versions are kept as saved.

**Validation.** Each engine release passes a statistical validation suite before it is shipped:

- sampling against the exact distributions, with every fallback;
- known answers;
- convergence coverage;
- aggregation;
- a reference scenario.

The engine also checks itself every time it starts. The platform refuses to run simulations on an engine whose validation did not pass. A change that alters results is always a new engine version.

## Warning codes

Warnings appear on a run with the estimate's place in the scenario (a JSON pointer such as `/lef/tef/contact_frequency`) and, where it applies, the control set.

| Code | Meaning |
|---|---|
| `point` | An estimate with minimum equal to maximum is a constant. |
| `domain_low` | An estimate's lower bound is set at its unit's limit; see [Fallbacks](#fallbacks). |
| `domain_high` | An estimate's upper bound is set at its unit's limit. |
| `bounds` | No distribution holds the estimate's confidence within its unit's limits; the estimate's range is treated as certain. |
| `reduction_capped` | A removed control's reduction above 99.9% is capped at 99.9%. |
| `probability_clipped` | Probability of action is clipped to 1 after a control's removal. |
| `resistance_removal_not_modelled` | Removing a control's resistance strength is not modelled. |
| `effect_not_modelled` | A threat capability or resistance strength effect has nothing to apply to (Vulnerability is entered directly). |
| `control_effect_changed` | A control's effect differs between the current set and this set. |
| `large_frequency` | Years with more than 1,000 loss events used the normal approximation beyond the first 1,000. |
| `loss_per_event_sampled` | Loss per event is summarized over a sample of the events. |
| `not_converged` | The relative standard error is above the threshold; use more iterations. |

## Failure codes

A run that fails stores no results. It records one of these:

| Code | Meaning |
|---|---|
| `invalid_bundle` | The scenario version cannot be simulated as it stands. The detail says where. |
| `engine_not_validated` | The engine's validation record did not pass, so the platform refused it. |
| `engine_unavailable` | The engine could not be reached after three attempts. Try again later. |
| `invalid_results` | The engine returned results that failed the platform's checks. |
| `engine_internal` | The engine failed while computing. |
