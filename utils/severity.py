def calculate_risk_score(summary):
    weights = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1
    }

    score = 0
    for level, count in summary.items():
        score += weights.get(level, 0) * count

    return score
