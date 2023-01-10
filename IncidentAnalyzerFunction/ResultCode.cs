using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IncidentAnalyzerFunction
{
    internal class ResultCode
    {
        public int Value { get; set; }
        public string Description { get; private set; }

        // NOTE: needs to be in sync with TestCase.TestNameToResultCodeDict
        public Dictionary<int, string> ValueToDescriptionDictionary = new Dictionary<int, string>()
        {
            { 1, "503.65 errors detected" },
            { 2, "SpikeInFrontendTraffic" },
            { 3, "SpikeInFrontendErrors" },
            { 4, "SpikeInTrafficToHostname" },
            { 5, "AzureStorageIssue" },
            { 6, "GeneralStorageIssue" },
            { 7, "FileServerIssue" },
            { 8, "WorkerErrorsForSLASites" },
            { 9, "TestForCongestedSMBPool" }
        };

        public ResultCode(int value)
        {
            Value = value;

            if (ValueToDescriptionDictionary.TryGetValue(value, out string description))
            {
                Description = description;
            }
            else
            {
                Description = "UnknownProblem";
            }
        }

        public override string ToString()
        {
            return Value + "&emsp;" + Description;
        }
    }
}
