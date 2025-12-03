"""
CLI tool to build prototypes using Farthest Point First (FPF) clustering.
"""
import sys
import argparse
import logging
from pathlib import Path

# Add parent directory to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.prototypes import build_prototypes
from src.config import SAMPLES_DIR, ROOT_DIR

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("build_prototypes")


def main():
    """Main function to build prototypes."""
    parser = argparse.ArgumentParser(
        description="Build prototypes using Farthest Point First (FPF) clustering"
    )
    parser.add_argument(
        "--samples-dir",
        type=str,
        default=str(SAMPLES_DIR),
        help="Path to samples directory"
    )
    parser.add_argument(
        "--k",
        type=int,
        default=5,
        help="Number of prototypes per class (default: 5)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(ROOT_DIR / "prototypes"),
        help="Output directory for prototypes"
    )
    
    args = parser.parse_args()
    
    try:
        logger.info("=" * 60)
        logger.info("Building Prototypes with FPF Clustering")
        logger.info("=" * 60)
        logger.info(f"Samples directory: {args.samples_dir}")
        logger.info(f"Prototypes per class: {args.k}")
        logger.info(f"Output directory: {args.output_dir}")
        logger.info("=" * 60)
        
        # Build prototypes
        results = build_prototypes(
            samples_dir=Path(args.samples_dir),
            k=args.k,
            output_dir=Path(args.output_dir)
        )
        
        # Print summary
        logger.info("")
        logger.info("=" * 60)
        logger.info("Prototype Building Summary")
        logger.info("=" * 60)
        
        if results["phishing"]["prototypes"]:
            logger.info(f"Phishing Prototypes: {len(results['phishing']['prototypes'])}/{results['phishing']['k']}")
            logger.info(f"  Selected from {results['phishing']['samples']} samples")
            logger.info(f"  Files: {', '.join(results['phishing']['prototypes'])}")
        
        if results["legitimate"]["prototypes"]:
            logger.info(f"Legitimate Prototypes: {len(results['legitimate']['prototypes'])}/{results['legitimate']['k']}")
            logger.info(f"  Selected from {results['legitimate']['samples']} samples")
            logger.info(f"  Files: {', '.join(results['legitimate']['prototypes'])}")
        
        logger.info("=" * 60)
        logger.info("Prototype building complete!")
        logger.info(f"Prototypes saved to: {args.output_dir}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Prototype building failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())


