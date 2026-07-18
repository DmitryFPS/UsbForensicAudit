using System;
using System.Collections.Generic;
using System.Linq;
using UsbForensicAudit;

var warnings = new List<string>();
var evidence = new List<EvidenceRecord>();
evidence.AddRange(new ExecutionArtifactCollector().Collect(warnings));
evidence.AddRange(new ProcessAttributionCollector().Collect(warnings));
Console.WriteLine($"Evidence={evidence.Count}");
Console.WriteLine("Warnings:");
foreach (var w in warnings) Console.WriteLine("  " + w);
var assessments = evidence.Select(e => new { e.EventId, e.Source, e.Summary, A = CleanerEvidenceClassifier.Analyze(e) })
  .Where(x => x.A != null)
  .ToList();
Console.WriteLine($"CleanerAssessments={assessments.Count}");
foreach (var a in assessments.Take(30))
  Console.WriteLine($"  {a.A!.Tool}|{a.A.Kind}|{a.EventId}|{a.Source}|{a.Summary}");
var tools = assessments.Where(x => x.A!.SupportsExecution).Select(x => x.A!.Tool).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
Console.WriteLine("ExecutionTools=" + string.Join(", ", tools));
