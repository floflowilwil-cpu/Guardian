namespace Guardian.AI.Risk;

/// <summary>
/// Applique une transformation sigmoïde paramétrée aux scores bruts.
/// Les paramètres par défaut ne constituent pas une calibration empirique démontrée;
/// ils doivent être ajustés et évalués sur un jeu de validation représentatif.
/// </summary>
public sealed class ProbabilityCalibrator
{
    // Valeurs de départ configurables, en attente d'une calibration sur un corpus documenté.
    private readonly double _parameterA;
    private readonly double _parameterB;

    /// <summary>
    /// Initialise le calibrateur avec des coefficients par défaut ou personnalisés.
    /// </summary>
    public ProbabilityCalibrator(double parameterA = -2.4, double parameterB = 0.15)
    {
        if (!double.IsFinite(parameterA))
        {
            throw new ArgumentOutOfRangeException(nameof(parameterA), "Le paramètre doit être fini.");
        }

        if (!double.IsFinite(parameterB))
        {
            throw new ArgumentOutOfRangeException(nameof(parameterB), "Le paramètre doit être fini.");
        }

        _parameterA = parameterA;
        _parameterB = parameterB;
    }

    /// <summary>
    /// Calibre un score de confiance brut [0.0, 1.0] vers une probabilité a posteriori calibrée.
    /// P(malveillant | score) = 1 / (1 + exp(A * score + B))
    /// </summary>
    public double Calibrate(double rawScore)
    {
        if (!double.IsFinite(rawScore) || rawScore < 0.0 || rawScore > 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(rawScore), "Le score brut doit être fini et compris entre 0 et 1.");
        }

        // Bornage de sécurité pour éviter les instabilités numériques
        double clampedRaw = Math.Clamp(rawScore, 0.001, 0.999);
        
        // Logit du score brut
        double logit = Math.Log(clampedRaw / (1.0 - clampedRaw));
        
        // Transformation sigmoïde calibrée
        double exponent = (_parameterA * logit) + _parameterB;
        double calibrated = 1.0 / (1.0 + Math.Exp(exponent));

        return Math.Round(Math.Clamp(calibrated, 0.0, 1.0), 4);
    }

    /// <summary>
    /// Calcule le score de Brier (erreur quadratique moyenne de calibration).
    /// </summary>
    public static double CalculateBrierScore(IReadOnlyList<(double CalibratedProb, bool ActualPositive)> evaluations)
    {
        if (evaluations.Count == 0)
        {
            return 0.0;
        }

        double sumSquaredError = 0.0;
        foreach (var (prob, actual) in evaluations)
        {
            if (!double.IsFinite(prob) || prob < 0.0 || prob > 1.0)
            {
                throw new ArgumentOutOfRangeException(nameof(evaluations), "Chaque probabilité doit être finie et comprise entre 0 et 1.");
            }

            double target = actual ? 1.0 : 0.0;
            double diff = prob - target;
            sumSquaredError += diff * diff;
        }

        return Math.Round(sumSquaredError / evaluations.Count, 4);
    }
}
