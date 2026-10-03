from fastapi import APIRouter

router = APIRouter(prefix="/campaign", tags=["Campaign Analytics"])


@router.get("/stats", summary="Get Phishing Campaign Aggregation Stats")
async def get_campaign_stats():
    """
    Endpoint for fetching campaign analytics and fraud trend statistics.
    """
    return {
        "status": "active",
        "message": "Campaign analysis infrastructure initialized.",
        "active_campaigns_monitored": 0
    }
