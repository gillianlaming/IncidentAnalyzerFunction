using Microsoft.Identity.Client.Extensions.Msal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using static Microsoft.IO.RecyclableMemoryStreamManager;

namespace IncidentAnalyzerFunction
{
    public class KustoQueries
    {
        // Please do not change the formatting of the kusto queries and let each line ally to the very left. It will beautify the query in the output UI.
        public static string StorageOverallAvaiabilityQuery(string stampName, string startTime, string endTime)
        { 
            return string.Format(@"AntaresStorageVolumeHealth  
                            | where EventPrimaryStampName == '{0}' 
                            | where TIMESTAMP between (datetime({1}) ..  datetime({2}))
                            | where (EventId == 55050 or EventId == 55051) and Status !contains ""cleaning up""
                            | extend Availability=iif(Status==""SUCCESS"",1,0), VolumeName = iif(VolumeRootPath endswith ""standby"",strcat(VolumeName,""-standby""), VolumeName)
                            | summarize avg(Availability) by bin(TIMESTAMP, 1m)",
                            stampName,
                            startTime,
                            endTime
                            );
        }

        public static string AzureStorageErrorQuery(string stampName, string startTime, string endTime)
        {
            return string.Format(@"XDriveEventTableV2
                            | where EventPrimaryStampName == '{0}' 
                            | where TIMESTAMP between (datetime({1}) ..  datetime({2}))
                            | where Role == ""FileServerRole""
                            | where VolumeType ==""RW""
                            | where EventId == 2
                            | where StorageErrorCode != ""SequenceNumberConditionNotMet"" and StorageErrorCode != ""Md5Mismatch""
                            | extend NtStatusInfo = strcat(""Error "", tostring(NtStatus))
                            | extend NtStatusInfo = iff(NtStatus == 3221225760, ""StatusCancelled"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221225997, ""StatusConnReset"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221225488, ""StatusInvalidDeviceRequest"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221225663, ""StatusNetworkBusy"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221225667, ""StatusInvalidNetworkResponse"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221226049, ""StatusConnAborted"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221225524, ""StatusObjectNameNotFound"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221225889, ""StatusInvalidLockRange"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221226538, ""StatusRequestOutOfSequence"", NtStatusInfo)
                            | extend NtStatusInfo = iff(NtStatus == 3221226038, ""StatusConnRefused"", NtStatusInfo)
                            | summarize count(),min(TIMESTAMP), max(TIMESTAMP) by NtStatusInfo",
                            stampName,
                            startTime,
                            endTime
                            );
        }

        public static string CheckForFileServerNetworkingIssue(string stampName, string startTime, string endTime)
        {
            return string.Format(@"XDriveEventTableV2
                            | where EventPrimaryStampName == '{0}'
                            | where TIMESTAMP between (datetime({1}) .. datetime({2}))
                            | where Role == ""FileServerRole""
                            | where VolumeType ==""RW""
                            | where EventId == 1
                            | where ConnEstablishmentDelayMs > 4900 and ConnEstablishmentDelayMs  < 5100
                            | summarize count() by RoleInstance",
                            stampName,
                            startTime,
                            endTime);
        }

        public static string FileServerRwLatencyQuery(string stampName, string startTime, string endTIme)
        {
            return string.Format(@"let ['_aggregationPeriod']='1m';
                                let ['_startTime']=datetime({1});
                                let ['_endTime']=datetime({2});
                                let ['_fileServerInstances']=dynamic(null);
                                let ['_primaryStampName']='{0}';
                                let actualAggregationPeriod=totimespan(_aggregationPeriod);
                                let roundedStartTime=bin(_startTime,actualAggregationPeriod);
                                let roundedEndTime=bin(_endTime,actualAggregationPeriod);
                                let  FileServerIpInfo=materialize(RoleInstanceHeartbeat
                                | where (EventPrimaryStampName == _primaryStampName)
                                | where TIMESTAMP between (_startTime.._endTime)
                                | where Role==""FileServerRole""
                                | summarize by RoleInstance,FsIpAddress=iff(isempty(PublicIpAddress),Details,PublicIpAddress), EventStampName
                                );
                                let beginEndTable=range TIMESTAMP from roundedStartTime to roundedEndTime step actualAggregationPeriod
                                | extend avgReadTimeInMs=toint(0), avgWriteTimeInMs=toint(0), FsRoleInstance=""_filler_"";
                                AntaresStorageVolumeHealth  
                                | where (EventPrimaryStampName == _primaryStampName)
                                | where TIMESTAMP  between (roundedStartTime..roundedEndTime) 
                                | where (EventId == 55050 or EventId == 55051) and Status !contains ""cleaning up""
                                | parse VolumeRootPath with @""\\"" FsIpAddress @""\"" FullVolumeName
                                | parse FullVolumeName with  ""volume-"" VolumeNum ""-"" VolumeType
                                | where VolumeType !endswith ""-standby""
                                | project TIMESTAMP, EventPrimaryStampName, FsIpAddress, WriteTimeTakenInMs, ReadTimeTakenInMs
                                | extend WriteTimeTakenInMs=iif(WriteTimeTakenInMs<0,0.0,WriteTimeTakenInMs)
                                | extend ReadTimeTakenInMs=iif(ReadTimeTakenInMs<0,0.0,ReadTimeTakenInMs)
                                | summarize avgReadTimeInMs=toint(avg(ReadTimeTakenInMs)), toint(avgWriteTimeInMs=avg(WriteTimeTakenInMs)) by bin(TIMESTAMP, actualAggregationPeriod), FsIpAddress
                                | join kind=leftouter (FileServerIpInfo) on FsIpAddress | project-away FsIpAddress1
                                | extend FsRoleInstance=iif(isempty(RoleInstance),FsIpAddress,RoleInstance)
                                | project-away RoleInstance, FsIpAddress
                                | project-reorder TIMESTAMP, FsRoleInstance,avgReadTimeInMs,avgWriteTimeInMs
                                | where isempty(_fileServerInstances) or FsRoleInstance in (_fileServerInstances)
                                | union beginEndTable
                                | summarize avg(avgReadTimeInMs), avg(avgWriteTimeInMs) by FsRoleInstance",
                                stampName,
                                startTime,
                                endTIme);
        }

        public static string GetDataRoleCacheConsistencyErrors(string startTime, string stampName)
        {
            return string.Format(@"AntaresRuntimeDataServiceEvents
                                | where PreciseTimeStamp between (datetime({0})..1h)
                                | where EventPrimaryStampName =~ '{1}'
                                | where EventId == 65452
                                | summarize count() by bin(PreciseTimeStamp, 10m), RoleInstance
                                | summarize Problematic10MinPeriods=countif(count_ > 10000) by RoleInstance
                                | where Problematic10MinPeriods >= 1",
                                startTime,
                                stampName);
        }

        public static string GetAzureStorageAccountName(string stampName)
        {
            return string.Format(@"AntaresFileServerEvents
            | where TIMESTAMP > ago(2h)
            | where EventPrimaryStampName == '{0}'
            | where EventId == 45036
            | where Operation == ""Mount""
            | project Details, EventPrimaryStampName
            | parse Details with * @""://"" StorageAccount1 ""."" *
            | extend StorageAccount = replace_string(StorageAccount1, ""-secondary"", """")
            | where EventPrimaryStampName !endswith ""dr""
            | summarize by StorageAccount", 
            stampName);
        }

        public static string FrontEndTrafficSpikeQuery(string stampName, string startTime)
        { 
            return string.Format(@"AntaresIISLogFrontEndTable
                            | where EventPrimaryStampName == '{0}'
                            | where PreciseTimeStamp between(datetime({1})..2h)
                            | summarize count() by bin(TIMESTAMP, 5m)
                            | summarize Max=max(count_), Min=min(count_), Avg=avg(count_) by bin(TIMESTAMP, 1h)
                            | extend MaxToAvgRatio = round((Max/Avg), 3)
                            | extend IsDDOSThreat = iff(MaxToAvgRatio > 1.8, 1, 0)
                            | summarize max(TIMESTAMP) by IsDDOSThreat, MaxToAvgRatio
                            | where IsDDOSThreat == 1
                            | order by max_TIMESTAMP asc",
                            stampName,
                            startTime);
        }

        public static string TrafficSpikeForSpecificHostQuery(string stampName, string startTime)
        { 
            return string.Format(@"AntaresIISLogFrontEndTable
                            | where EventPrimaryStampName == '{0}'
                            | where PreciseTimeStamp between(datetime({1})..1h)
                            | summarize count() by bin(TIMESTAMP, 5m), Cs_host
                            | where count_ > 500000
                            | summarize max(count_), round(avg(count_), 1) by Cs_host
                            | sort by max_count_ desc
                            | take 5",
                            stampName,
                            startTime);
        }

        public static string FrontEndSpikesErrorQuery(string stampName, string startTime)
        { 
            return string.Format(@"let base = AntaresIISLogFrontEndTable 
                            | where (EventStampName == '{0}') 
                            | where TIMESTAMP between(datetime({1})..5h)
                            | where Sc_status >= 500
                            | extend RoleInstance=strcat(substring(EventStampName, strlen(EventStampName)-3, strlen(EventStampName)),""-"",RoleInstance);
                            let stressedFes = base | summarize count() by RoleInstance | order by count_ | take 16 | project RoleInstance;
                            base 
                            | where RoleInstance in (stressedFes)
                            | summarize count() by bin(TIMESTAMP, 1m), RoleInstance
                            | summarize Avg = round(avg(count_),1), max(count_) by bin(TIMESTAMP, 30m)
                            | where Avg > 1000",
                            stampName,
                            startTime);
        }

        public static string NoAvailableWorkersQuery(string stampName, string startTime, string endTime)
        { 
            return string.Format(@"AntaresIISLogFrontEndTable
                            | where EventPrimaryStampName == '{0}'
                            | where PreciseTimeStamp between(datetime({1})..3h)
                            | where Sc_status == 503 and Sc_substatus == 65
                            | where Cs_host startswith 'mawscanary'
                            | summarize count()",
                            stampName,
                            startTime,
                            endTime);
        }

        public static string GetStampInformationQuery(string stampName)
        {
            return String.Format(@"let eventPrimaryStampName = '{0}';
                                        let start = ago(1h);
                                        let end = now();
                                        let stamp=eventPrimaryStampName;
                                        let heartbeats = materialize(RoleInstanceHeartbeat | where EventPrimaryStampName== stamp and TIMESTAMP between(start..end));
                                        let linuxHeartbeats = materialize(LinuxRoleInstanceHeartBeats | where EventPrimaryStampName == stamp and TIMESTAMP between(start..end));
                                        let tenants=materialize(heartbeats | summarize by EventStampName );
                                        let IsMegastamp=toscalar(tenants | summarize x=dcount(EventStampName) | project iff(x > 1, 'True', 'False'));
                                        let IsFlexStamp=toscalar(tenants | where EventStampName endswith ""data"" | summarize x=dcount(EventStampName) | project iff(x > 0, ""True"", ""False""));
                                        let IsSingleTenantStamp=toscalar(tenants | summarize x=dcount(EventStampName) | project iff(x == 1, ""True"", ""False""));
                                        let isVmssStamp = toscalar(heartbeats | where ((Role startswith ""dw"" or Role startswith ""xn"") or (EventStampType =~ ""MiniStamp"" and Tenant == EventStampName))
                                        | union (linuxHeartbeats | where Role startswith ""lw"")
                                        | take 1 | summarize x=count() | project Value=iff(x == 0, ""False"", ""True""));
                                        let SupportsHyperVContainers = toscalar(heartbeats | where (Role startswith ""xn"" or IsXenon==1) | take 1 | summarize x=count() | project Value=iff(x == 0, ""False"", ""True""));
                                        let HasPv3 = toscalar(heartbeats | where Role startswith ""wn"" 
                                        | union (linuxHeartbeats | where Role startswith ""ln"")| take 1 | summarize x=count() | project Value=iff(x == 0, ""False"", ""True""));
                                        let isAzEnabled = toscalar(heartbeats | where (Role startswith ""dw"" or Role startswith ""xn"") | extend UpgradeDomain = toint(UpgradeDomain)
                                        | union (linuxHeartbeats | where Role startswith ""lw"" | extend UpgradeDomain = toint(UpgradeDomain))
                                        | take 100 | summarize x=max(UpgradeDomain) | project Value=iff(x > 5, ""True"", ""False""));
                                        let isHybridStamp = toscalar(heartbeats
                                        | extend IsVmssTenant = iff(Tenant == stamp, ""True"", ""False"")
                                        | summarize x = dcount(IsVmssTenant)
                                        | project iff(x > 1, ""True"", ""False""));
                                        let isLinuxStamp = toscalar(linuxHeartbeats | take 1 | summarize x=count() | project Value=iff(x==0, ""False"", ""True""));
                                        let isMiniStamp = toscalar(heartbeats | take 1 | project Value=tostring(EventStampType =~ ""MiniStamp""));
                                        union
	                                        (print Name=""Is a single tenant stamp"", Value=IsSingleTenantStamp),
	                                        (print Name=""Is a megastamp"", Value=IsMegastamp),
	                                        (print Name=""Is a flexstamp"", Value=IsFlexStamp),
	                                        (print Name=""Is a VMSS stamp"", Value=isVmssStamp),
	                                        (print Name=""Is AZ enabled"", Value=isAzEnabled),
	                                        (print Name=""Hyper-V Containers"", Value=SupportsHyperVContainers),
	                                        (print Name=""Has Pv3"", Value=HasPv3),
	                                        (print Name=""Is a hybrid stamp"",  Value=isHybridStamp),
	                                        (print Name=""Is a linux stamp"", Value=isLinuxStamp),
	                                        (print Name=""Is a ministamp"", Value=isMiniStamp)
                                        | order by Name asc",
                                        stampName);
        }

        public static string GetRecentDeploymentInformationQuery(string stampName, string startTime)
        {
            return String.Format(@"let globalTo = datetime({0});
                                All('AntaresCloudDeploymentEvents')
                                | where TIMESTAMP between((globalTo-5d)..globalTo) and EnvironmentName =~ '{1}' and EventId in (64013)
                                | summarize StartTime=min(TIMESTAMP),arg_max(EndTime=TIMESTAMP,TemplateName,Details) by DeploymentId
                                | extend Duration=EndTime-StartTime
                                | extend EndTime=iif(Details startswith 'Deployment finished',EndTime,todatetime(""""))",
                                startTime,
                                stampName);
        }

        public static string GetImpactedSubscriptionInformationQuery(string stampName, string startTime)
        {
            return string.Format(@"CanaryRunnerPingsGeneva
                                | where TIMESTAMP > (datetime({0})-30min) and TIMESTAMP < datetime({0})
                                and Stamp =~ '{1}'
                                | where HealthStatus != ""Healthy""
                                | distinct SubscriptionId",
                                startTime,
                                stampName);
            
        }

        public static string DetectErrorsOnWorkerForSLASites(string stampName, string startTime)
        {
            return String.Format(@"AntaresIISLogWorkerTable
                                | where TIMESTAMP between(datetime({0})..4h)
                                | where EventPrimaryStampName =~ '{1}'
                                | where S_sitename contains ""sla-ws""
                                | where Sc_status >= 500
                                | summarize count() by Sc_status, Sc_substatus, Sc_win32_status, EventIpAddress
                                | where count_ > 5
                                | sort by count_ desc",
                                startTime,
                                stampName);
        }

        public static string HighlyCongestedSMBPoolQuery(string stampName, string startTime)
        {
            return string.Format(@"// FileServer experiencing High Levels of Congestion in SMB Pool for over 1 hour
                                    // Smallest SMB Pool size in Prod is 40
                                    let heavyCongestionThreshold=30;
                                    let aggregationPeriod=5m;
                                    let analysisWindowLength=120m;
                                    let kustoDelaySkipPeriod=10m;
                                    let roundedEndTime=bin(datetime({0})-kustoDelaySkipPeriod,aggregationPeriod);
                                    let roundedStartTime=bin(roundedEndTime-analysisWindowLength, aggregationPeriod);
                                    let dashboardStartTime=roundedStartTime-1h;
                                    // Find roles with at least some hight level of congestion
                                    let RolesWithHighCongestion=WadFilterEvents
                                    | where TIMESTAMP between (roundedStartTime..roundedEndTime)
                                    | where EventId in (1, 2)
                                    | where EventStampType == ""Stamp""
                                    | where EventPrimaryStampName =~ '{1}'
                                    | extend BlockingThreadpoolActivity=CntCreates + CntQueryInformation + CntSetInformation + CntSetSecurity + CntQuerySecurity + CntQueryDirectory + CntCloses + CntCleanups
                                    | summarize AvgPendingBlockingActivity=avgif(BlockingThreadpoolActivity, EventId==1), AvgCompletedBlockingActivity=avgif(BlockingThreadpoolActivity, EventId==2) by bin(TIMESTAMP, aggregationPeriod), EventPrimaryStampName, EventStampName, RoleInstance, DiskNumber
                                    | summarize AvgCompletedBlockingActivity=sum(AvgCompletedBlockingActivity), AvgPendingBlockingActivity=sum(AvgPendingBlockingActivity) by TIMESTAMP, EventPrimaryStampName, EventStampName, RoleInstance
                                    | where AvgPendingBlockingActivity > heavyCongestionThreshold
                                    | distinct EventPrimaryStampName, EventStampName, RoleInstance;
                                    // Filter out short spurious congestion
                                    WadFilterEvents
                                    | where TIMESTAMP between (roundedStartTime..roundedEndTime)
                                    | where EventId in (1, 2)
                                    | join kind=inner RolesWithHighCongestion on EventPrimaryStampName, EventStampName, RoleInstance
                                    | extend BlockingThreadpoolActivity=CntCreates + CntQueryInformation + CntSetInformation + CntSetSecurity + CntQuerySecurity + CntQueryDirectory + CntCloses + CntCleanups
                                    | summarize AvgPendingBlockingActivity=avgif(BlockingThreadpoolActivity, EventId==1), AvgCompletedBlockingActivity=avgif(BlockingThreadpoolActivity, EventId==2) by bin(TIMESTAMP, aggregationPeriod), EventPrimaryStampName, RoleInstance, DiskNumber
                                    | summarize AvgCompletedBlockingActivity=sum(AvgCompletedBlockingActivity), AvgPendingBlockingActivity=sum(AvgPendingBlockingActivity) by TIMESTAMP, EventPrimaryStampName, RoleInstance
                                    | extend HeavyPoolCongestion=iff(AvgPendingBlockingActivity > heavyCongestionThreshold, 1, 0)
                                    | summarize HeavyCongestionCount=sum(HeavyPoolCongestion), SampleCount=count() by EventPrimaryStampName, RoleInstance
                                    | extend CongestionDurationPercent = (todouble(HeavyCongestionCount)/SampleCount)*100.0
                                    | where (CongestionDurationPercent > 40)",
                                    startTime,
                                    stampName);
        }

        public static string IdentifyProblematicVolumeForCongestedFileServer(string stampName, string startTime, string fileServerRoleInstance)
        {
            return string.Format(@"SMBEvents
                                | where EventId == 1020 
                                | where TIMESTAMP between (datetime({0})..1h)
                                | where EventPrimaryStampName =~ '{1}'
                                | where Role == ""FileServerRole""
                                | where RoleInstance =~ '{2}'
                                | where ShareName !contains ""-standby""
                                | parse ShareName with @""\\*\"" VolumeName ""-default""
                                | summarize Count=count() by VolumeName
                                | order by Count desc
                                | take 1",
                                startTime,
                                stampName,
                                fileServerRoleInstance);
        }
    }
}
