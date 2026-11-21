"""Offline socket policy inherited by local-demo Python descendants only."""
import os

if os.environ.get('TWINGUARD_OFFLINE') == '1':
    from local_demo import offline_guard
    offline_guard()
