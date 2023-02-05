#pragma once

class MetricModuleDigestMismatch : public Metric {
public:
	eMetricType GetType();
	eMetrics GetIndex();
	void OnMetric();
};