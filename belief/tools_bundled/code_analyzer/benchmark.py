"""Performance benchmarking for code-analyzer.

Runs analysis on test projects and records timing/memory metrics.
"""

import time
import tracemalloc
from pathlib import Path
from code_analyzer.analyzer import CodeAnalyzer


def benchmark_project(project_path: str, project_name: str, depth: str = "shallow"):
    """Benchmark a single project."""
    print(f"\n{'='*60}")
    print(f"Benchmarking: {project_name}")
    print(f"Path: {project_path}")
    print(f"Depth: {depth}")
    print(f"{'='*60}")
    
    # Start timing and memory tracking
    tracemalloc.start()
    start_time = time.time()
    
    try:
        # Run analysis
        analyzer = CodeAnalyzer(project_path)
        result = analyzer.analyze(depth=depth)
        
        # Get metrics
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Calculate results
        duration = end_time - start_time
        peak_mb = peak / 1024 / 1024
        
        # Print results
        print(f"\n✅ SUCCESS")
        print(f"\nTiming:")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Files/sec: {result.metrics.total_files / duration:.1f}")
        
        print(f"\nMemory:")
        print(f"  Peak: {peak_mb:.1f} MB")
        print(f"  Per file: {peak_mb / max(result.metrics.total_files, 1):.2f} MB")
        
        print(f"\nCode Metrics:")
        print(f"  Files: {result.metrics.total_files}")
        print(f"  Lines: {result.metrics.total_lines:,}")
        print(f"  Classes: {result.metrics.total_classes}")
        print(f"  Functions: {result.metrics.total_functions}")
        print(f"  Complexity: {result.metrics.average_complexity:.2f} avg")
        
        print(f"\nAnalysis Results:")
        print(f"  Modules: {len(result.modules)}")
        print(f"  Issues: {len(result.issues)}")
        print(f"  Critical sections: {len(result.critical_sections)}")
        
        return {
            'project': project_name,
            'success': True,
            'duration': duration,
            'peak_memory_mb': peak_mb,
            'files': result.metrics.total_files,
            'lines': result.metrics.total_lines,
            'files_per_sec': result.metrics.total_files / duration,
            'lines_per_sec': result.metrics.total_lines / duration,
        }
        
    except Exception as e:
        print(f"\n❌ FAILED: {e}")
        tracemalloc.stop()
        return {
            'project': project_name,
            'success': False,
            'error': str(e)
        }


def main():
    """Run benchmarks on test projects."""
    print("\n" + "="*60)
    print("CODE-ANALYZER PERFORMANCE BENCHMARKS")
    print("="*60)
    
    # Define test projects
    projects = [
        ("/Volumes/Projects/code-analyzer", "code-analyzer (self)"),
        ("/Volumes/Projects/repo-tickets", "repo-tickets"),
        ("/Volumes/Projects/agentscript", "agentscript"),
        ("/Volumes/Projects/logseq-python", "logseq-python (filtered)"),
    ]
    
    results = []
    
    # Run benchmarks
    for project_path, project_name in projects:
        if Path(project_path).exists():
            result = benchmark_project(project_path, project_name, depth="shallow")
            results.append(result)
        else:
            print(f"\n⚠️  Skipping {project_name} - path not found")
    
    # Print summary
    print(f"\n\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    
    successful = [r for r in results if r.get('success')]
    
    if successful:
        print(f"\nProjects analyzed: {len(successful)}")
        
        total_files = sum(r['files'] for r in successful)
        total_lines = sum(r['lines'] for r in successful)
        total_time = sum(r['duration'] for r in successful)
        avg_memory = sum(r['peak_memory_mb'] for r in successful) / len(successful)
        
        print(f"\nTotals:")
        print(f"  Files: {total_files}")
        print(f"  Lines: {total_lines:,}")
        print(f"  Time: {total_time:.2f}s")
        print(f"  Avg memory: {avg_memory:.1f} MB")
        
        print(f"\nThroughput:")
        print(f"  Files/sec: {total_files / total_time:.1f}")
        print(f"  Lines/sec: {total_lines / total_time:,.0f}")
        
        print(f"\nPer-project averages:")
        print(f"  Duration: {total_time / len(successful):.2f}s")
        print(f"  Memory: {avg_memory:.1f} MB")
        
        # Find fastest/slowest
        fastest = min(successful, key=lambda r: r['duration'])
        slowest = max(successful, key=lambda r: r['duration'])
        
        print(f"\nFastest: {fastest['project']} ({fastest['duration']:.2f}s)")
        print(f"Slowest: {slowest['project']} ({slowest['duration']:.2f}s)")
    
    print(f"\n{'='*60}")
    print("Benchmark complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
