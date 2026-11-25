using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Anomaly;

/// <summary>
/// Détecteur d'anomalies non supervisé basé sur l'algorithme Isolation Forest (iForest).
/// Isole les anomalies structurelles ou comportementales atypiques en mesurant la profondeur de partitionnement.
/// </summary>
public sealed class IsolationForestAnomalyDetector : IAnomalyDetector
{
    private sealed class IsolationTreeNode
    {
        public int FeatureIndex { get; set; } = -1;
        public double SplitValue { get; set; }
        public double MinValue { get; set; }
        public double MaxValue { get; set; }
        public int Size { get; set; }
        public IsolationTreeNode? Left { get; set; }
        public IsolationTreeNode? Right { get; set; }
        public bool IsLeaf => Left == null && Right == null;
    }

    private readonly List<IsolationTreeNode> _trees = [];
    private readonly int _treeCount;
    private readonly int _subSampleSize;
    private readonly double _anomalyThreshold;
    private readonly double _cFactor;

    /// <summary>
    /// Initialise la forêt d'isolation avec les hyperparamètres recommandés.
    /// </summary>
    public IsolationForestAnomalyDetector(int treeCount = 64, int subSampleSize = 128, double anomalyThreshold = 0.65)
    {
        _treeCount = treeCount;
        _subSampleSize = subSampleSize;
        _anomalyThreshold = anomalyThreshold;
        _cFactor = CalculateAveragePathLength(_subSampleSize);

        TrainBaselineTrees();
    }

    public Task<AnomalyDetectionResult> DetectAnomalyAsync(
        AnomalyEvaluationContext context, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (context.FeatureVector.Length == 0)
        {
            return Task.FromResult(new AnomalyDetectionResult
            {
                EntityId = context.EntityId,
                IsAnomaly = false,
                AnomalyScore = 0.0,
                Confidence = 0.5,
                Explanation = "Vecteur de caractéristiques vide."
            });
        }

        double totalPathLength = 0.0;
        foreach (var tree in _trees)
        {
            totalPathLength += PathLength(context.FeatureVector, tree, 0);
        }

        double averagePathLength = totalPathLength / _trees.Count;
        
        // s = 2 ^ (- E(h(x)) / c(n))
        double anomalyScore = Math.Pow(2.0, -averagePathLength / _cFactor);
        anomalyScore = Math.Round(Math.Clamp(anomalyScore, 0.0, 1.0), 4);

        bool isAnomaly = anomalyScore >= _anomalyThreshold;
        double confidence = Math.Clamp(0.5 + Math.Abs(anomalyScore - 0.5), 0.5, 0.98);

        string explanation = isAnomaly
            ? $"Observation hautement atypique (score: {anomalyScore:F2} >= seuil {_anomalyThreshold:F2}). Le profil a été isolé en seulement {averagePathLength:F1} partitions (moyenne de référence: {_cFactor:F1})."
            : $"Observation conforme à la distribution normale (score: {anomalyScore:F2} < seuil {_anomalyThreshold:F2}). Profondeur moyenne de partitionnement: {averagePathLength:F1}.";

        return Task.FromResult(new AnomalyDetectionResult
        {
            EntityId = context.EntityId,
            IsAnomaly = isAnomaly,
            AnomalyScore = anomalyScore,
            Confidence = Math.Round(confidence, 4),
            Explanation = explanation
        });
    }

    private void TrainBaselineTrees()
    {
        // Données d'entraînement de référence synthétisées représentant le comportement d'applications saines standard
        // Features: [Taille, Entropie, NbrSections, APIAppels, ValidSig, PackerIndicator]
        var random = new Random(42);
        var baselineData = new List<double[]>();

        for (int i = 0; i < 256; i++)
        {
            baselineData.Add([
                random.Next(50000, 5000000),      // FileSize
                4.5 + (random.NextDouble() * 2.0), // Entropy 4.5 - 6.5
                random.Next(3, 7),                 // Sections 3 - 6
                random.Next(0, 2),                 // Suspicious APIs 0 - 1
                1.0,                               // Valid Sig
                0.0                                // Packer 0
            ]);
        }

        int maxDepth = (int)Math.Ceiling(Math.Log2(_subSampleSize));

        for (int t = 0; t < _treeCount; t++)
        {
            var sample = baselineData.OrderBy(_ => random.Next()).Take(_subSampleSize).ToList();
            _trees.Add(BuildTree(sample, 0, maxDepth, random));
        }
    }

    private static IsolationTreeNode BuildTree(List<double[]> data, int currentDepth, int maxDepth, Random random)
    {
        var node = new IsolationTreeNode { Size = data.Count };

        if (currentDepth >= maxDepth || data.Count <= 1)
        {
            return node;
        }

        int featureCount = data[0].Length;
        int featureIndex = random.Next(featureCount);

        double min = data.Min(x => x[featureIndex]);
        double max = data.Max(x => x[featureIndex]);

        if (Math.Abs(max - min) < 0.0001)
        {
            return node;
        }

        double splitValue = min + (random.NextDouble() * (max - min));

        var leftData = data.Where(x => x[featureIndex] < splitValue).ToList();
        var rightData = data.Where(x => x[featureIndex] >= splitValue).ToList();

        if (leftData.Count == 0 || rightData.Count == 0)
        {
            return node;
        }

        node.FeatureIndex = featureIndex;
        node.MinValue = min;
        node.MaxValue = max;
        node.SplitValue = splitValue;
        node.Left = BuildTree(leftData, currentDepth + 1, maxDepth, random);
        node.Right = BuildTree(rightData, currentDepth + 1, maxDepth, random);

        return node;
    }

    private static double PathLength(double[] x, IsolationTreeNode node, int currentDepth)
    {
        if (node.IsLeaf)
        {
            return currentDepth + CalculateAveragePathLength(node.Size);
        }

        if (node.FeatureIndex < 0 || node.FeatureIndex >= x.Length)
        {
            return currentDepth;
        }

        // Si la valeur est en dehors de la plage observée pour cette partition,
        // elle est isolée immédiatement
        if (x[node.FeatureIndex] < node.MinValue || x[node.FeatureIndex] > node.MaxValue)
        {
            return currentDepth + 1.0;
        }

        if (x[node.FeatureIndex] < node.SplitValue)
        {
            return node.Left != null ? PathLength(x, node.Left, currentDepth + 1) : currentDepth;
        }

        return node.Right != null ? PathLength(x, node.Right, currentDepth + 1) : currentDepth;
    }

    private static double CalculateAveragePathLength(int n)
    {
        if (n <= 1)
        {
            return 0.0;
        }
        if (n == 2)
        {
            return 1.0;
        }

        const double eulerMascheroni = 0.5772156649;
        return 2.0 * (Math.Log(n - 1) + eulerMascheroni) - (2.0 * (n - 1) / n);
    }
}
