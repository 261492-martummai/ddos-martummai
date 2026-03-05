import warnings

warnings.filterwarnings(
    "ignore",
    message=r".*sklearn.utils.parallel.delayed.*",
    category=UserWarning,
)
