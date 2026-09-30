using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Json;
using BenchmarkDotNet.Reports;

namespace Aegis.Auth.Benchmarks.Infrastructure;

internal static class BenchConfig
{
    public static IConfig Create() => DefaultConfig.Instance
        .AddDiagnoser(MemoryDiagnoser.Default)
        .AddColumn(CategoriesColumn.Default)
        .AddExporter(MarkdownExporter.GitHub)
        .AddExporter(JsonExporter.Full)
        .WithSummaryStyle(SummaryStyle.Default.WithRatioStyle(RatioStyle.Trend))
        .WithOptions(ConfigOptions.DisableLogFile);
}
