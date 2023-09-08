from dataclasses import dataclass

@dataclass()
class MetricConfig():
    ylabel: str
    metric: str
    title: str

METRIC = {
    'execs/s': MetricConfig('Test case executions per seconds', 'execs_per_sec', "Fuzzing speed comparison")
}
