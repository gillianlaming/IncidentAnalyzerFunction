﻿using System;
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
            { 1, "NotEnoughWorkers" },
            { 2, "SpikeInFrontendTraffic" },
            { 3, "SpikeInFrontendErrors" },
            { 4, "SpikeInTrafficToHostname" },
            { 5, "AzureStorageIssue" },
            { 6, "GeneralStorageIssue" },
            { 7, "File Server Issue and CHeck Storage Volume Auto-Isolation" },
            { 8, "WorkerErrorsForSLASites" },
            { 9, "Congested SMB Pool and Check Storage Volume Auto-Isolation" },
            { 10, "DataRoleCacheConsistencyErrors" },
            { 11, "FileServerNetworkConnectivityIssues" },
            { 12, "HostingDbCPUHightIssue"}
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
            return Value + " " + Description;
        }

    }
}
