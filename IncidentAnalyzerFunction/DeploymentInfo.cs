using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IncidentAnalyzerFunction
{
    internal class DeploymentInfo
    {

        public string DeploymentId;
        public string StartTime;
        public string EndTime;
        public string TemplateName;
        public string Details;

        public DeploymentInfo()
        {

        }

        public DeploymentInfo(string deploymentId, string startTime, string endTime, string templateName, string details)
        {
            DeploymentId = deploymentId;
            StartTime = startTime;
            EndTime = endTime;
            TemplateName = templateName;
            Details = details;
        }

    }
}
