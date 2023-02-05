#pragma once

enum eMetricType {
	METRIC_NONE,
	METRIC_WARNING,
	METRIC_DISABLE_ACCOUNT
};

enum eMetrics {
	METRICS_NONE,
	METRICS_INTEGRITY_CHECK_FAILED,
	METRICS_BREAKPOINT,
	METRICS_MODULE_DIGEST_MISMATCH
};

class Metric {
public:
	virtual eMetricType GetType();
	virtual eMetrics GetIndex();
	virtual void OnMetric();
};

void ProcessMetric(Metric* pMetric, const char* pExtraInfo = nullptr);