from fastapi import APIRouter
from typing import List, Dict, Any
from ..models.schemas import ResearchMetric
from ..demo_data.benchmark_dataset import get_research_benchmark_metrics, BENCHMARK_SAMPLES

router = APIRouter(prefix="/api/research", tags=["Research"])

@router.get("/metrics", response_model=List[ResearchMetric])
def get_metrics():
    """Returns empirical benchmark metrics comparing Traditional, AI-Only, and VULNEX Hybrid."""
    return get_research_benchmark_metrics()

@router.get("/samples")
def get_benchmark_samples():
    """Returns the ground-truth benchmark dataset containing vulnerable and secure test cases."""
    return {
        "total_samples": len(BENCHMARK_SAMPLES),
        "categories": list(set(s["category"] for s in BENCHMARK_SAMPLES)),
        "samples": BENCHMARK_SAMPLES
    }
