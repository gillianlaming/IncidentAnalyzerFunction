using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using YamlDotNet.Core.Tokens;

namespace IncidentAnalyzerFunction
{
    internal class TestCase: IEquatable<TestCase>, IComparable<TestCase>
    {
        private ResultCode _code;
        public string TestName { get; set; }
        public TestResult Result { get; set; }
        public ConcurrentBag<string> ActionSuggestions = new ConcurrentBag<string>();

        public ResultCode Code 
        {
            get
            {
                if (Result.Equals(TestResult.Passed))
                {
                    _code = new ResultCode(0);
                }
                else
                {
                    TestNameToResultCodeDict.TryGetValue(TestName, out int rc);
                    _code = new ResultCode(rc);
                }

                return _code;
            }
            private set
            {
                _code = value;
            }
        }

        public ConcurrentBag<string> ResultMessage = new ConcurrentBag<string>();

        // NOTE: needs to be in sync with ResultCode.ValueToDescriptionDictionary
        public Dictionary<string, int> TestNameToResultCodeDict = new Dictionary<string, int>()
        {
            { "TestFor503_65:NotEnoughWorkersAvailable", 1},
            { "TestForSpikeInFrontEndTraffic", 2 },
            { "TestSpikeInFrontEndErrors", 3 },
            { "TestTrafficSpikeForSpecificHost", 4 },
            { "TestForAzureStorageIssue", 5 },
            { "TestForStorageIssue", 6 },
            { "TestForFileServerIssue", 7 },
            { "TestForProblemWorkersForSLASites", 8 }
        };

        public TestCase(string testName)
        {
            TestName = testName;
        }

        public override string ToString()
        {
            string specificTestDetails = GetSpecificFindingsFromTest(); // this will print on a new line!
            return PadTestName(TestName) + " ----------------->  " + Result.ToString() + specificTestDetails;
        }

        public bool Equals(TestCase tc)
        {
            if (tc == null) return false;
            return TestName == tc.TestName;
        }

        public override bool Equals(object obj)
        {
            TestCase t1 = obj as TestCase;
            if (t1 == null) return false;
            return Equals(t1);
        }

        public int CompareTo(TestCase other)
        {
            if (Result != other.Result)
            {
                if (Result == TestResult.Passed)
                {
                    return -1;
                }
                else
                {
                    return 1;
                }
            }
            else
            {
                // they are equal
                return 0;
            }
        }

        public enum TestResult
        {
            Passed,
            ProblemDetected
        }

        private int GetMaxLengthOfTestCaseName()
        {
            int maxLen = 0;
            foreach (string key in TestNameToResultCodeDict.Keys)
            {
                maxLen = Math.Max(maxLen, key.Length);
            }
            return maxLen;
        }

        private string GetSpecificFindingsFromTest()
        {
            string resultString = "";
            foreach (var item in ResultMessage)
            {
                if (String.IsNullOrEmpty(item))
                {
                    continue;
                }

                resultString += item + "\n";
            }

            return resultString;
        }

        private string PadTestName(string testName)
        {
            int maxLen = GetMaxLengthOfTestCaseName();
            string paddedTestName = testName;
            for(int i = testName.Length; i < maxLen; i++)
            {
                paddedTestName += " ";
            }

            return paddedTestName;
        }
    }
}
