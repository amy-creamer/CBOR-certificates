import numpy as np
import matplotlib.pyplot as plt

# Generate synthetic "Olympic-like" data
np.random.seed(0)
years = np.linspace(1900, 2020, 40)
true_line = 12 - 0.01*(years - 1900)

# Heteroscedastic noise: big early, small late
noise_sd = np.linspace(0.5, 0.05, len(years))
observed = true_line + np.random.randn(len(years)) * noise_sd

# Fake Bayesian-style predictive intervals
# (wide early, narrow late)
pred_mean = true_line
pred_sd = noise_sd  # just reuse for the illustration
upper = pred_mean + 2*pred_sd
lower = pred_mean - 2*pred_sd

plt.figure(figsize=(10,5))
plt.scatter(years, observed, label="Observed data", alpha=0.7)
plt.plot(years, pred_mean, label="Estimated trend (mean)")
plt.fill_between(years, lower, upper, alpha=0.2, label="Uncertainty interval")
plt.xlabel("Year")
plt.ylabel("Winning time (seconds)")
plt.title("Illustration: Wide uncertainty early, narrow uncertainty later")
plt.legend()
plt.show()
