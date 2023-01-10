using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IncidentAnalyzerFunction
{
    public class FormattingHelper
    {
        public static string HeadingPrefix = "<h1 style='font-size:19px;'>";
        public static string HeadingSuffix = "</h1>";
        public static string PassedTestPrefix = "<p style='color:green;'>";
        public static string PassedTestSuffix = "</p>";
        public static string FailedTestPrefix = "<p style='color:red;'>";
        public static string FailedTestSuffix = "</p>";
        public static string TitlePrefix = "<h1 style='font-size:30px; color:blue;'>";
        public static string TitleSuffix = "</h1>";
        public static string ActionSuggestionPrefix = "<p style='color:orange; font-size:20px'>";
        public static string ActionSuggestionSuffix = "</p>";

        public static string FormatHeading(string line)
        {
            return HeadingPrefix + line + HeadingSuffix;
        }

        public static string FormatPassedTest(string line)
        {
            return PassedTestPrefix + line + PassedTestSuffix;
        }

        public static string FormatFailedTest(string line)
        {
            return FailedTestPrefix + line + FailedTestSuffix;
        }

        public static string FormatActionSuggestion(string line)
        {
            return ActionSuggestionPrefix + line + ActionSuggestionSuffix;
        }

        public static string FormatTitle(string line)
        {
            return TitlePrefix + line + TitleSuffix;
        }


    }
}
