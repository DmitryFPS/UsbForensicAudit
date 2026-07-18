using System;
using System.Collections.Generic;
using System.Linq;
using UsbForensicAudit;

var warnings = new List<string>();
var evidence = new List<EvidenceRecord>();
evidence.AddRange(new ExecutionArtifactCollector().Collect(warnings));
evidence.AddRange(new ProcessAttributionCollector().Collect(warnings));
Console.WriteLine($"Evidence: {evidence.Count}");
Console.WriteLine("Warnings:");
foreach (var w in warnings) Console.WriteLine("  " + w);
var assessed = evidence.Select(e => new { e.EventId, e.Source, e.Summary, A = CleanerEvidenceClassifier.Analyze(e) }).Where(x => x.A != null).ToList();
Console.WriteLine($"Assessed: {assessed.Count}");
foreach (var x in assessed.Take(30))
  Console.WriteLine($"  {x.A!.Kind} | {x.A.Tool} | {x.EventId} | {x.Source} | {x.Summary}");
var tools = assessed.Where(x => x.A!.SupportsExecution).Select(x => x.A.Tool).Distinct(StringComparer.OrdinalIgnoreCase);
Console.WriteLine("Exec tools: " + string.Join(", ", tools));
