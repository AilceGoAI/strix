"""Build switch for the self-hosted edition.

Gating UI with this flag instead of deleting code keeps upstream merges cheap:
a re-base only has to re-apply the few branches that read it.
"""

LOCAL_EDITION = True
