/* eslint-disable @typescript-eslint/ban-types */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-empty-interface */

export interface Tag {
  Key: string;
  Value: string;
}

export interface AWS_WAFRegional_ByteMatchSet____ByteMatchTuple {
  TargetString?: string;
  TargetStringBase64?: string;
  PositionalConstraint: string;
  TextTransformation: string;
  FieldToMatch: AWS_WAFRegional_ByteMatchSet____FieldToMatch;
}

export interface AWS_AppMesh_VirtualRouter____PortMapping {
  Port: number;
  Protocol: string;
}

export interface JoinKeyProperties {
  UniqueKey?: boolean;
}

export interface AWS_ElastiCache_ReplicationGroup____LogDeliveryConfigurationRequest {
  DestinationDetails?: AWS_ElastiCache_ReplicationGroup____DestinationDetails;
  DestinationType?: string;
  LogFormat?: string;
  LogType?: string;
}

export interface IncrementalPullConfig {
  DatetimeTypeFieldName?: string;
}

export interface FileFormatDescriptor {
  CsvFormatDescriptor?: CsvFormatDescriptor;
  JsonFormatDescriptor?: JsonFormatDescriptor;
}

export interface AWS_Greengrass_CoreDefinition____Core {
  SyncShadow?: boolean;
  ThingArn: string;
  Id: string;
  CertificateArn: string;
}

export interface FindMatchesParameters {
  PrecisionRecallTradeoff?: number;
  EnforceProvidedLabels?: boolean;
  PrimaryKeyColumnName: string;
  AccuracyCostTradeoff?: number;
}

export interface WorkGroupConfigurationUpdates {
  BytesScannedCutoffPerQuery?: number;
  EnforceWorkGroupConfiguration?: boolean;
  PublishCloudWatchMetricsEnabled?: boolean;
  RequesterPaysEnabled?: boolean;
  ResultConfigurationUpdates?: ResultConfigurationUpdates;
  RemoveBytesScannedCutoffPerQuery?: boolean;
  EngineVersion?: EngineVersion;
}

export interface AWS_Greengrass_FunctionDefinitionVersion____FunctionConfiguration {
  MemorySize?: number;
  Pinned?: boolean;
  ExecArgs?: string;
  Timeout?: number;
  EncodingType?: string;
  Environment?: AWS_Greengrass_FunctionDefinitionVersion____Environment;
  Executable?: string;
}

export type AWS_SageMaker_MonitoringSchedule____Environment = undefined;

export interface AWS_S3_AccessPoint____PublicAccessBlockConfiguration {
  BlockPublicAcls?: boolean;
  IgnorePublicAcls?: boolean;
  BlockPublicPolicy?: boolean;
  RestrictPublicBuckets?: boolean;
}

export interface AWS_ElasticBeanstalk_Environment____OptionSetting {
  Namespace: string;
  OptionName: string;
  ResourceName?: string;
  Value?: string;
}

export interface AWS_EventSchemas_Schema____TagsEntry {
  Value: string;
  Key: string;
}

export interface PrefixLevelStorageMetrics {
  IsEnabled?: boolean;
  SelectionCriteria?: SelectionCriteria;
}

export interface DatasetContentVersionValue {
  DatasetName?: string;
}

export interface KinesisSettings {
  MessageFormat?: string;
  StreamArn?: string;
  ServiceAccessRoleArn?: string;
}

export interface EventSelector {
  DataResources?: Array<DataResource>;
  IncludeManagementEvents?: boolean;
  ReadWriteType?: string;
}

export interface InsightsConfiguration {
  InsightsEnabled?: boolean;
  NotificationsEnabled?: boolean;
}

export interface AWS_IoT_TopicRule____AssetPropertyVariant {
  StringValue?: string;
  DoubleValue?: string;
  BooleanValue?: string;
  IntegerValue?: string;
}

export interface S3Settings {
  ExternalTableDefinition?: string;
  BucketName?: string;
  BucketFolder?: string;
  CsvRowDelimiter?: string;
  CsvDelimiter?: string;
  ServiceAccessRoleArn?: string;
  CompressionType?: string;
}

export interface AWS_AutoScaling_LaunchConfiguration____BlockDeviceMapping {
  DeviceName: string;
  Ebs?: BlockDevice;
  NoDevice?: boolean;
  VirtualName?: string;
}

export interface Cookies {
  Forward: string;
  WhitelistedNames?: Array<string>;
}

export interface OwnershipControls {
  Rules: Array<OwnershipControlsRule>;
}

export interface AWS_EMR_Step____HadoopJarStepConfig {
  Args?: Array<string>;
  Jar: string;
  MainClass?: string;
  StepProperties?: Array<AWS_EMR_Step____KeyValue>;
}

export interface BillingMode {
  Mode: string;
  ProvisionedThroughput?: AWS_Cassandra_Table____ProvisionedThroughput;
}

export interface AWS_WAFv2_RuleGroup____JsonMatchPattern {
  All?: any;
  IncludedPaths?: Array<string>;
}

export interface ReplicaModifications {
  Status: string;
}

export interface AWS_AutoScaling_AutoScalingGroup____LaunchTemplateOverrides {
  InstanceType?: string;
  LaunchTemplateSpecification?: AWS_AutoScaling_AutoScalingGroup____LaunchTemplateSpecification;
  WeightedCapacity?: string;
}

export interface Extensions {
  CertificatePolicies?: Array<PolicyInformation>;
  ExtendedKeyUsage?: Array<ExtendedKeyUsage>;
  KeyUsage?: AWS_ACMPCA_Certificate____KeyUsage;
  SubjectAlternativeNames?: Array<AWS_ACMPCA_Certificate____GeneralName>;
}

export interface InforNexusConnectorProfileProperties {
  InstanceUrl: string;
}

export interface DataSourceParameters {
  AuroraPostgreSqlParameters?: AuroraPostgreSqlParameters;
  TeradataParameters?: TeradataParameters;
  RdsParameters?: RdsParameters;
  AthenaParameters?: AthenaParameters;
  SparkParameters?: SparkParameters;
  MariaDbParameters?: MariaDbParameters;
  OracleParameters?: OracleParameters;
  PrestoParameters?: PrestoParameters;
  RedshiftParameters?: RedshiftParameters;
  MySqlParameters?: MySqlParameters;
  SqlServerParameters?: SqlServerParameters;
  SnowflakeParameters?: SnowflakeParameters;
  AmazonElasticsearchParameters?: AmazonElasticsearchParameters;
  PostgreSqlParameters?: PostgreSqlParameters;
  AuroraParameters?: AuroraParameters;
  S3Parameters?: S3Parameters;
}

export interface TlsValidationContextSdsTrust {
  SecretName: string;
}

export interface DatabaseInput {
  LocationUri?: string;
  Description?: string;
  Parameters?: any;
  TargetDatabase?: DatabaseIdentifier;
  Name?: string;
}

export interface PostgreSqlSettings {
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface AWS_ACMPCA_Certificate____Subject {
  Country?: string;
  Organization?: string;
  OrganizationalUnit?: string;
  DistinguishedNameQualifier?: string;
  State?: string;
  CommonName?: string;
  SerialNumber?: string;
  Locality?: string;
  Title?: string;
  Surname?: string;
  GivenName?: string;
  Initials?: string;
  Pseudonym?: string;
  GenerationQualifier?: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____RecordColumn {
  Mapping?: string;
  SqlType: string;
  Name: string;
}

export interface PasswordPolicy {
  RequireNumbers?: boolean;
  MinimumLength?: number;
  TemporaryPasswordValidityDays?: number;
  RequireUppercase?: boolean;
  RequireLowercase?: boolean;
  RequireSymbols?: boolean;
}

export interface CapacityProviderStrategy {
  Base?: number;
  Weight?: number;
  CapacityProvider: string;
}

export interface AWS_KinesisAnalytics_ApplicationOutput____KinesisFirehoseOutput {
  ResourceARN: string;
  RoleARN: string;
}

export interface OrganizationAggregationSource {
  AllAwsRegions?: boolean;
  AwsRegions?: Array<string>;
  RoleArn: string;
}

export interface ShutdownEventConfiguration {
  DelayUntilElbConnectionsDrained?: boolean;
  ExecutionTimeout?: number;
}

export interface AuroraPostgreSqlParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface Volumes {
  Host?: VolumesHost;
  EfsVolumeConfiguration?: EfsVolumeConfiguration;
  Name?: string;
}

export interface FilterExpression {
  Expression: string;
  ValuesMap: Array<FilterValue>;
}

export interface StepScalingPolicyConfiguration {
  AdjustmentType?: string;
  Cooldown?: number;
  MetricAggregationType?: string;
  MinAdjustmentMagnitude?: number;
  StepAdjustments?: Array<AWS_ApplicationAutoScaling_ScalingPolicy____StepAdjustment>;
}

export interface DeviceShadowEnrich {
  Attribute?: string;
  Next?: string;
  ThingName?: string;
  RoleArn?: string;
  Name?: string;
}

export interface CorsRule {
  AllowedHeaders?: Array<string>;
  AllowedMethods: Array<string>;
  AllowedOrigins: Array<string>;
  ExposedHeaders?: Array<string>;
  Id?: string;
  MaxAge?: number;
}

export interface AWS_WAFv2_RuleGroup____XssMatchStatement {
  FieldToMatch: AWS_WAFv2_RuleGroup____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_RuleGroup____TextTransformation>;
}

export interface CsvFormatDescriptor {
  FileCompression?: string;
  Charset?: string;
  Delimiter?: string;
  HeaderList?: Array<string>;
  QuoteSymbol?: string;
  ContainsHeader?: boolean;
}

export interface AWS_ImageBuilder_ImagePipeline____ImageTestsConfiguration {
  ImageTestsEnabled?: boolean;
  TimeoutMinutes?: number;
}

export interface AWS_DirectoryService_MicrosoftAD____VpcSettings {
  SubnetIds: Array<string>;
  VpcId: string;
}

export interface RelationalDatabaseConfig {
  RdsHttpEndpointConfig?: RdsHttpEndpointConfig;
  RelationalDatabaseSourceType: string;
}

export interface AWS_Lambda_Function____VpcConfig {
  SecurityGroupIds: Array<string>;
  SubnetIds: Array<string>;
}

export interface DomainEndpointOptions {
  CustomEndpoint?: string;
  CustomEndpointCertificateArn?: string;
  CustomEndpointEnabled?: boolean;
  EnforceHTTPS?: boolean;
  TLSSecurityPolicy?: string;
}

export interface S3RecordingConfig {
  BucketArn?: string;
  RoleArn?: string;
  Prefix?: string;
}

export interface SetTimer {
  DurationExpression?: string;
  Seconds?: number;
  TimerName: string;
}

export interface AWS_AppMesh_Route____Duration {
  Value: number;
  Unit: string;
}

export interface ComponentPlatform {
  Name?: string;
  Attributes?: Record<string, string>;
}

export interface UploadSettings {
  ContainsHeader?: boolean;
  TextQualifier?: string;
  Format?: string;
  StartFromRow?: number;
  Delimiter?: string;
}

export interface RecoveryOption {
  Priority?: number;
  Name?: string;
}

export interface WeightedTarget {
  VirtualNode: string;
  Weight: number;
}

export interface NodeConfiguration {
  AvailabilityZone: string;
  InstanceType: string;
}

export interface DataSource {
  Arn?: string;
  DatabaseName?: string;
  Type?: string;
}

export interface AWS_S3_Bucket____Destination {
  BucketAccountId?: string;
  BucketArn: string;
  Format: string;
  Prefix?: string;
}

export interface WafAction {
  Type: string;
}

export interface ResetTimer {
  TimerName: string;
}

export interface AWS_NetworkFirewall_RuleGroup____ActionDefinition {
  PublishMetricAction?: AWS_NetworkFirewall_RuleGroup____PublishMetricAction;
}

export interface AWS_WAF_IPSet____IPSetDescriptor {
  Type: string;
  Value: string;
}

export interface IotEvents {
  InputName: string;
  Payload?: Payload;
}

export interface AWS_DataSync_Task____FilterRule {
  FilterType?: string;
  Value?: string;
}

export interface TransitionEvent {
  Actions?: Array<AWS_IoTEvents_DetectorModel____Action>;
  Condition: string;
  EventName: string;
  NextState: string;
}

export interface AWS_ApiGateway_Deployment____MethodSetting {
  CacheDataEncrypted?: boolean;
  CacheTtlInSeconds?: number;
  CachingEnabled?: boolean;
  DataTraceEnabled?: boolean;
  HttpMethod?: string;
  LoggingLevel?: string;
  MetricsEnabled?: boolean;
  ResourcePath?: string;
  ThrottlingBurstLimit?: number;
  ThrottlingRateLimit?: number;
}

export interface ComputeLimits {
  MaximumCapacityUnits: number;
  MaximumCoreCapacityUnits?: number;
  MaximumOnDemandCapacityUnits?: number;
  MinimumCapacityUnits: number;
  UnitType: string;
}

export interface VirtualGatewayTlsValidationContextTrust {
  SDS?: VirtualGatewayTlsValidationContextSdsTrust;
  ACM?: VirtualGatewayTlsValidationContextAcmTrust;
  File?: VirtualGatewayTlsValidationContextFileTrust;
}

export interface AWS_EMR_Cluster____SpotProvisioningSpecification {
  AllocationStrategy?: string;
  BlockDurationMinutes?: number;
  TimeoutAction: string;
  TimeoutDurationMinutes: number;
}

export interface VolumeConfiguration {
  Encrypted?: boolean;
  Iops?: number;
  MountPoint?: string;
  NumberOfDisks?: number;
  RaidLevel?: number;
  Size?: number;
  VolumeType?: string;
}

export interface SigV4Authorization {
  ServiceName: string;
  SigningRegion: string;
  RoleArn: string;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____ClusterConfig {
  InstanceCount: number;
  InstanceType: string;
  VolumeKmsKeyId?: string;
  VolumeSizeInGB: number;
}

export interface AWS_AppConfig_Deployment____Tags {
  Value?: string;
  Key?: string;
}

export interface BootstrapActionConfig {
  Name: string;
  ScriptBootstrapAction: ScriptBootstrapActionConfig;
}

export interface AWS_Lambda_Alias____ProvisionedConcurrencyConfiguration {
  ProvisionedConcurrentExecutions: number;
}

export interface NotificationChannelConfig {
  Sns?: SnsChannelConfig;
}

export interface ConfigSnapshotDeliveryProperties {
  DeliveryFrequency?: string;
}

export interface AWS_ResourceGroups_Group____TagFilter {
  Key?: string;
  Values?: Array<string>;
}

export interface AWS_ECR_ReplicationConfiguration____ReplicationConfiguration {
  Rules: Array<AWS_ECR_ReplicationConfiguration____ReplicationRule>;
}

export interface GlueConfiguration {
  TableName: string;
  DatabaseName: string;
}

export interface AccessPointTag {
  Key?: string;
  Value?: string;
}

export interface AWS_AutoScaling_ScalingPolicy____CustomizedMetricSpecification {
  Dimensions?: Array<AWS_AutoScaling_ScalingPolicy____MetricDimension>;
  MetricName: string;
  Namespace: string;
  Statistic: string;
  Unit?: string;
}

export interface SheetControlsOption {
  VisibilityState?: string;
}

export interface SqsAction {
  RoleArn: string;
  UseBase64?: boolean;
  QueueUrl: string;
}

export interface DynatraceConnectorProfileCredentials {
  ApiToken: string;
}

export interface UplinkEchoConfig {
  Enabled?: boolean;
  AntennaUplinkConfigArn?: string;
}

export interface AWS_StepFunctions_Activity____TagsEntry {
  Value: string;
  Key: string;
}

export interface AWS_KinesisFirehose_DeliveryStream____EncryptionConfiguration {
  KMSEncryptionConfig?: KMSEncryptionConfig;
  NoEncryptionConfig?: string;
}

export interface AWS_ECS_TaskDefinition____LogConfiguration {
  LogDriver: string;
  Options?: Record<string, string>;
  SecretOptions?: Array<AWS_ECS_TaskDefinition____Secret>;
}

export interface PrefixConfig {
  PrefixType?: string;
  PrefixFormat?: string;
}

export interface InputFormatConfiguration {
  Deserializer?: Deserializer;
}

export interface DataQualityBaselineConfig {
  BaseliningJobName?: string;
  ConstraintsResource?: AWS_SageMaker_DataQualityJobDefinition____ConstraintsResource;
  StatisticsResource?: AWS_SageMaker_DataQualityJobDefinition____StatisticsResource;
}

export interface AWS_QuickSight_Analysis____DecimalParameter {
  Values: Array<number>;
  Name: string;
}

export interface RevocationConfiguration {
  CrlConfiguration?: CrlConfiguration;
}

export interface PutItemInput {
  TableName: string;
}

export interface CustomRequestHandling {
  InsertHeaders: Array<CustomHTTPHeader>;
}

export interface TCPFlagField {
  Flags: Array<string>;
  Masks?: Array<string>;
}

export interface FirelensConfiguration {
  Type?: string;
  Options?: Record<string, string>;
}

export interface AccessLoggingPolicy {
  EmitInterval?: number;
  Enabled: boolean;
  S3BucketName: string;
  S3BucketPrefix?: string;
}

export interface AWS_SageMaker_DataQualityJobDefinition____StatisticsResource {
  S3Uri?: string;
}

export interface AddThingsToThingGroupParams {
  OverrideDynamicGroups?: boolean;
  ThingGroupNames: Array<string>;
}

export interface RecipeStep {
  Action: AWS_DataBrew_Recipe____Action;
  ConditionExpressions?: Array<ConditionExpression>;
}

export interface AWS_ECS_TaskDefinition____Device {
  ContainerPath?: string;
  HostPath?: string;
  Permissions?: Array<string>;
}

export interface LambdaContainerParams {
  MemorySizeInKB?: number;
  MountROSysfs?: boolean;
  Volumes?: Array<LambdaVolumeMount>;
  Devices?: Array<LambdaDeviceMount>;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____RecordFormat {
  MappingParameters?: AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____MappingParameters;
  RecordFormatType: string;
}

export interface CopyActionResourceType {
  Lifecycle?: LifecycleResourceType;
  DestinationBackupVaultArn: string;
}

export interface AWS_GameLift_GameServerGroup____TargetTrackingConfiguration {
  TargetValue: number;
}

export interface ConnectionPoolConfigurationInfoFormat {
  MaxConnectionsPercent?: number;
  MaxIdleConnectionsPercent?: number;
  ConnectionBorrowTimeout?: number;
  SessionPinningFilters?: Array<string>;
  InitQuery?: string;
}

export interface JobCommand {
  PythonVersion?: string;
  ScriptLocation?: string;
  Name?: string;
}

export interface FleetLaunchTemplateSpecificationRequest {
  LaunchTemplateName?: string;
  Version?: string;
  LaunchTemplateId?: string;
}

export interface ManagedRuleGroupStatement {
  Name: string;
  VendorName: string;
  ExcludedRules?: Array<ExcludedRule>;
  ScopeDownStatement?: AWS_WAFv2_WebACL____Statement;
}

export interface OwnershipControlsRule {
  ObjectOwnership?: string;
}

export interface LocalSecondaryIndex {
  IndexName: string;
  KeySchema: Array<KeySchema>;
  Projection: Projection;
}

export interface DBInstanceRole {
  FeatureName: string;
  RoleArn: string;
}

export interface Provider {
  KeyArn?: string;
}

export interface MarketoConnectorProfileCredentials {
  ClientId: string;
  ClientSecret: string;
  AccessToken?: string;
  ConnectorOAuthRequest?: ConnectorOAuthRequest;
}

export interface VpnTunnelOptionsSpecification {
  PreSharedKey?: string;
  TunnelInsideCidr?: string;
}

export interface MicrosoftSqlServerSettings {
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface SnsAction {
  TargetArn: string;
  MessageFormat?: string;
  RoleArn: string;
}

export interface FastRestoreRule {
  IntervalUnit?: string;
  AvailabilityZones?: Array<string>;
  Count?: number;
  Interval?: number;
}

export interface StepConfig {
  ActionOnFailure?: string;
  HadoopJarStep: AWS_EMR_Cluster____HadoopJarStepConfig;
  Name: string;
}

export interface NodeToNodeEncryptionOptions {
  Enabled?: boolean;
}

export interface AWS_GuardDuty_Filter____FindingCriteria {
  Criterion?: any;
  ItemType?: AWS_GuardDuty_Filter____Condition;
}

export interface MetricStat {
  Metric: AWS_CloudWatch_Alarm____Metric;
  Period: number;
  Stat: string;
  Unit?: string;
}

export interface DeltaTimeSessionWindowConfiguration {
  TimeoutInMinutes: number;
}

export interface DocumentRequires {
  Name?: string;
  Version?: string;
}

export interface ElasticsearchClusterConfig {
  DedicatedMasterCount?: number;
  DedicatedMasterEnabled?: boolean;
  DedicatedMasterType?: string;
  InstanceCount?: number;
  InstanceType?: string;
  WarmCount?: number;
  WarmEnabled?: boolean;
  WarmType?: string;
  ZoneAwarenessConfig?: ZoneAwarenessConfig;
  ZoneAwarenessEnabled?: boolean;
}

export interface AWS_Lambda_Function____DeadLetterConfig {
  TargetArn?: string;
}

export interface RedshiftConnectorProfileCredentials {
  Username: string;
  Password: string;
}

export interface AWS_Greengrass_FunctionDefinitionVersion____Execution {
  IsolationMode?: string;
  RunAs?: AWS_Greengrass_FunctionDefinitionVersion____RunAs;
}

export interface DataSourceCredentials {
  CopySourceArn?: string;
  CredentialPair?: CredentialPair;
}

export interface TrafficMirrorPortRange {
  FromPort: number;
  ToPort: number;
}

export interface KernelGatewayImageConfig {
  FileSystemConfig?: AWS_SageMaker_AppImageConfig____FileSystemConfig;
  KernelSpecs: Array<KernelSpec>;
}

export interface AWS_Lambda_Function____FileSystemConfig {
  Arn: string;
  LocalMountPath: string;
}

export interface VpcDestinationProperties {
  SubnetIds?: Array<string>;
  SecurityGroups?: Array<string>;
  VpcId?: string;
  RoleArn?: string;
}

export interface SourceIpConfig {
  Values?: Array<string>;
}

export interface BudgetData {
  BudgetLimit?: Spend;
  TimePeriod?: TimePeriod;
  TimeUnit: string;
  PlannedBudgetLimits?: any;
  CostFilters?: any;
  BudgetName?: string;
  CostTypes?: CostTypes;
  BudgetType: string;
}

export interface S3ContentLocation {
  BucketARN?: string;
  FileKey?: string;
  ObjectVersion?: string;
}

export interface AWS_Batch_JobDefinition____AuthorizationConfig {
  Iam?: string;
  AccessPointId?: string;
}

export interface IotSiteWise {
  AssetId?: string;
  EntryId?: string;
  PropertyAlias?: string;
  PropertyId?: string;
  PropertyValue: AWS_IoTEvents_DetectorModel____AssetPropertyValue;
}

export interface ApiStage {
  ApiId?: string;
  Stage?: string;
  Throttle?: Record<string, ThrottleSettings>;
}

export interface RecordingGroup {
  AllSupported?: boolean;
  IncludeGlobalResourceTypes?: boolean;
  ResourceTypes?: Array<string>;
}

export interface ResourceServerScopeType {
  ScopeName: string;
  ScopeDescription: string;
}

export interface ZendeskConnectorProfileProperties {
  InstanceUrl: string;
}

export interface AWS_MediaConnect_Flow____Encryption {
  Algorithm: string;
  ConstantInitializationVector?: string;
  DeviceId?: string;
  KeyType?: string;
  Region?: string;
  ResourceId?: string;
  RoleArn: string;
  SecretArn?: string;
  Url?: string;
}

export interface ScalingConfiguration {
  AutoPause?: boolean;
  MaxCapacity?: number;
  MinCapacity?: number;
  SecondsUntilAutoPause?: number;
}

export interface AWS_SageMaker_Endpoint____Alarm {
  AlarmName: string;
}

export interface S3Config {
  BucketAccessRoleArn: string;
}

export interface CredentialPair {
  AlternateDataSourceParameters?: Array<DataSourceParameters>;
  Username: string;
  Password: string;
}

export interface AutoRollbackConfig {
  Alarms: Array<AWS_SageMaker_Endpoint____Alarm>;
}

export interface AWS_WAFv2_WebACL____TextTransformation {
  Priority: number;
  Type: string;
}

export interface AWS_EC2_LaunchTemplate____BlockDeviceMapping {
  Ebs?: AWS_EC2_LaunchTemplate____Ebs;
  NoDevice?: string;
  VirtualName?: string;
  DeviceName?: string;
}

export interface AWS_AutoScaling_LaunchConfiguration____MetadataOptions {
  HttpEndpoint?: string;
  HttpPutResponseHopLimit?: number;
  HttpTokens?: string;
}

export interface SpotOptions {
  SpotInstanceType?: string;
  InstanceInterruptionBehavior?: string;
  MaxPrice?: string;
  BlockDurationMinutes?: number;
  ValidUntil?: string;
}

export interface OutputFileUriValue {
  FileName?: string;
}

export interface AccessControlTranslation {
  Owner: string;
}

export interface UpdateCACertificateParams {
  Action: string;
}

export interface AWS_QuickSight_Analysis____ResourcePermission {
  Actions: Array<string>;
  Principal: string;
}

export interface AWS_CodeStar_GitHubRepository____Code {
  S3: AWS_CodeStar_GitHubRepository____S3;
}

export interface ClientPolicyTls {
  Validation: TlsValidationContext;
  Enforce?: boolean;
  Ports?: Array<number>;
  Certificate?: ClientTlsCertificate;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____ResourceInstance {
  ResourceDataContainer: AWS_Greengrass_ResourceDefinitionVersion____ResourceDataContainer;
  Id: string;
  Name: string;
}

export interface AWS_WAFRegional_Rule____Predicate {
  Type: string;
  DataId: string;
  Negated: boolean;
}

export interface AWS_EC2_Instance____HibernationOptions {
  Configured?: boolean;
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule____AuthenticateOidcConfig {
  OnUnauthenticatedRequest?: string;
  TokenEndpoint: string;
  SessionTimeout?: number;
  Scope?: string;
  Issuer: string;
  ClientSecret: string;
  UserInfoEndpoint: string;
  ClientId: string;
  AuthorizationEndpoint: string;
  SessionCookieName?: string;
  UseExistingClientSecret?: boolean;
  AuthenticationRequestExtraParams?: Record<string, string>;
}

export interface AWS_ImageBuilder_ImageRecipe____InstanceBlockDeviceMapping {
  DeviceName?: string;
  VirtualName?: string;
  NoDevice?: string;
  Ebs?: AWS_ImageBuilder_ImageRecipe____EbsInstanceBlockDeviceSpecification;
}

export interface GrpcRouteMetadataMatchMethod {
  Suffix?: string;
  Regex?: string;
  Exact?: string;
  Prefix?: string;
  Range?: MatchRange;
}

export interface SpotPlacement {
  AvailabilityZone?: string;
  GroupName?: string;
  Tenancy?: string;
}

export interface AWS_Greengrass_FunctionDefinition____FunctionConfiguration {
  MemorySize?: number;
  Pinned?: boolean;
  ExecArgs?: string;
  Timeout?: number;
  EncodingType?: string;
  Environment?: AWS_Greengrass_FunctionDefinition____Environment;
  Executable?: string;
}

export interface Font {
  FontFamily?: string;
}

export interface AWS_Greengrass_LoggerDefinitionVersion____Logger {
  Space?: number;
  Type: string;
  Level: string;
  Id: string;
  Component: string;
}

export interface Delegation {
  LastUpdated?: number;
  ControlSetId?: string;
  CreationTime?: number;
  CreatedBy?: string;
  RoleArn?: string;
  AssessmentName?: string;
  Comment?: string;
  Id?: string;
  RoleType?: string;
  AssessmentId?: string;
  Status?: string;
}

export interface AWS_S3_Bucket____VersioningConfiguration {
  Status: string;
}

export interface TargetGroupInfo {
  Name?: string;
}

export interface AWS_KinesisAnalytics_Application____CSVMappingParameters {
  RecordRowDelimiter: string;
  RecordColumnDelimiter: string;
}

export interface AWS_EC2_NetworkInterface____InstanceIpv6Address {
  Ipv6Address: string;
}

export interface VirtualGatewayListenerTlsAcmCertificate {
  CertificateArn: string;
}

export interface AllowAction {
  CustomRequestHandling?: CustomRequestHandling;
}

export interface SourceBundle {
  S3Bucket: string;
  S3Key: string;
}

export interface SuspendedState {
  DynamicScalingInSuspended?: boolean;
  DynamicScalingOutSuspended?: boolean;
  ScheduledScalingSuspended?: boolean;
}

export interface DataLocationResource {
  S3Resource?: string;
  CatalogId?: string;
}

export interface AWS_IoTAnalytics_Dataset____Filter {
  DeltaTime?: DeltaTime;
}

export interface AWS_NetworkManager_Device____Location {
  Address?: string;
  Latitude?: string;
  Longitude?: string;
}

export interface HttpAction {
  ConfirmationUrl?: string;
  Headers?: Array<HttpActionHeader>;
  Url: string;
  Auth?: HttpAuthorization;
}

export interface HostedZoneTag {
  Key: string;
  Value: string;
}

export interface DefaultAction {
  Allow?: AllowAction;
  Block?: BlockAction;
}

export type AWS_AppSync_GraphQLApi____Tags = Tag[];

export interface AWS_ElasticLoadBalancingV2_ListenerRule____AuthenticateCognitoConfig {
  OnUnauthenticatedRequest?: string;
  UserPoolClientId: string;
  UserPoolDomain: string;
  SessionTimeout?: number;
  Scope?: string;
  SessionCookieName?: string;
  UserPoolArn: string;
  AuthenticationRequestExtraParams?: Record<string, string>;
}

export interface PutAssetPropertyValueEntry {
  PropertyAlias?: string;
  PropertyValues: Array<AWS_IoT_TopicRule____AssetPropertyValue>;
  AssetId?: string;
  EntryId?: string;
  PropertyId?: string;
}

export interface FileAccessLog {
  Path: string;
}

export interface QueryStringKeyValue {
  Value?: string;
  Key?: string;
}

export interface AWS_Greengrass_ResourceDefinition____S3MachineLearningModelResourceData {
  OwnerSetting?: AWS_Greengrass_ResourceDefinition____ResourceDownloadOwnerSetting;
  DestinationPath: string;
  S3Uri: string;
}

export interface MetricTransformation {
  DefaultValue?: number;
  MetricName: string;
  MetricNamespace: string;
  MetricValue: string;
}

export interface S3OutputFormatConfig {
  FileType?: string;
  PrefixConfig?: PrefixConfig;
  AggregationConfig?: AggregationConfig;
}

export interface ResourceValue {
  Value?: string;
}

export interface ReplicationTime {
  Status: string;
  Time: ReplicationTimeValue;
}

export interface AWS_Lambda_EventInvokeConfig____OnFailure {
  Destination: string;
}

export interface PlacementStrategy {
  Field?: string;
  Type: string;
}

export interface MetricToRetain {
  Metric: string;
  MetricDimension?: AWS_IoT_SecurityProfile____MetricDimension;
}

export interface ComputeResources {
  SpotIamFleetRole?: string;
  MaxvCpus: number;
  Ec2Configuration?: Array<Ec2ConfigurationObject>;
  BidPercentage?: number;
  SecurityGroupIds?: Array<string>;
  Subnets: Array<string>;
  Type: string;
  AllocationStrategy?: string;
  MinvCpus?: number;
  LaunchTemplate?: AWS_Batch_ComputeEnvironment____LaunchTemplateSpecification;
  ImageId?: string;
  InstanceRole?: string;
  InstanceTypes?: Array<string>;
  Ec2KeyPair?: string;
  PlacementGroup?: string;
  Tags?: any;
  DesiredvCpus?: number;
}

export interface Bandwidth {
  DownloadSpeed?: number;
  UploadSpeed?: number;
}

export interface AccountTakeoverActionsType {
  HighAction?: AccountTakeoverActionType;
  LowAction?: AccountTakeoverActionType;
  MediumAction?: AccountTakeoverActionType;
}

export interface AWS_CloudFront_CachePolicy____HeadersConfig {
  HeaderBehavior: string;
  Headers?: Array<string>;
}

export interface RiskExceptionConfigurationType {
  BlockedIPRangeList?: Array<string>;
  SkippedIPRangeList?: Array<string>;
}

export interface DataflowEndpointConfig {
  DataflowEndpointName?: string;
  DataflowEndpointRegion?: string;
}

export interface AWS_S3Outposts_Bucket____AbortIncompleteMultipartUpload {
  DaysAfterInitiation: number;
}

export interface StageKey {
  RestApiId?: string;
  StageName?: string;
}

export type PatchStringDate = string;

export interface ServerSideEncryptionByDefault {
  KMSMasterKeyID?: string;
  SSEAlgorithm: string;
}

export interface AWS_EMR_Cluster____EbsBlockDeviceConfig {
  VolumeSpecification: AWS_EMR_Cluster____VolumeSpecification;
  VolumesPerInstance?: number;
}

export interface AWS_NetworkFirewall_FirewallPolicy____CustomAction {
  ActionName: string;
  ActionDefinition: AWS_NetworkFirewall_FirewallPolicy____ActionDefinition;
}

export interface CatalogTarget {
  DatabaseName?: string;
  Tables?: Array<string>;
}

export interface AWS_Batch_JobDefinition____ResourceRequirement {
  Type?: string;
  Value?: string;
}

export interface SelectionCriteria {
  MaxDepth?: number;
  Delimiter?: string;
  MinStorageBytesPercentage?: number;
}

export interface BorderStyle {
  Show?: boolean;
}

export interface AWS_LakeFormation_DataLakeSettings____DataLakePrincipal {
  DataLakePrincipalIdentifier?: string;
}

export interface SubComponentConfigurationDetails {
  AlarmMetrics?: Array<AlarmMetric>;
  Logs?: Array<Log>;
  WindowsEvents?: Array<WindowsEvent>;
}

export interface SelectAttributes {
  Next?: string;
  Attributes?: Array<string>;
  Name?: string;
}

export interface RotationRules {
  AutomaticallyAfterDays?: number;
}

export interface AWS_CodeBuild_Project____Environment {
  Type: string;
  EnvironmentVariables?: Array<AWS_CodeBuild_Project____EnvironmentVariable>;
  PrivilegedMode?: boolean;
  ImagePullCredentialsType?: string;
  Image: string;
  RegistryCredential?: RegistryCredential;
  ComputeType: string;
  Certificate?: string;
}

export interface Tiering {
  AccessTier: string;
  Days: number;
}

export interface AWS_WAFv2_WebACL____XssMatchStatement {
  FieldToMatch: AWS_WAFv2_WebACL____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_WebACL____TextTransformation>;
}

export interface KeyGroupConfig {
  Comment?: string;
  Items: Array<string>;
  Name: string;
}

export interface ProjectOperation {
  ProjectedColumns: Array<string>;
}

export interface MultiModelConfig {
  ModelCacheSetting?: string;
}

export interface ColumnLevelPermissionRule {
  ColumnNames?: Array<string>;
  Principals?: Array<string>;
}

export interface OriginRequestPolicyConfig {
  Comment?: string;
  CookiesConfig: AWS_CloudFront_OriginRequestPolicy____CookiesConfig;
  HeadersConfig: AWS_CloudFront_OriginRequestPolicy____HeadersConfig;
  Name: string;
  QueryStringsConfig: AWS_CloudFront_OriginRequestPolicy____QueryStringsConfig;
}

export interface ManagedScalingPolicy {
  ComputeLimits?: ComputeLimits;
}

export interface DataflowEdge {
  Source?: string;
  Destination?: string;
}

export interface DynamoDB {
  HashKeyField: string;
  HashKeyType?: string;
  HashKeyValue: string;
  Operation?: string;
  Payload?: Payload;
  PayloadField?: string;
  RangeKeyField?: string;
  RangeKeyType?: string;
  RangeKeyValue?: string;
  TableName: string;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____S3Output {
  LocalPath: string;
  S3UploadMode?: string;
  S3Uri: string;
}

export interface AWS_WAFv2_WebACL____ByteMatchStatement {
  SearchString?: string;
  SearchStringBase64?: string;
  FieldToMatch: AWS_WAFv2_WebACL____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_WebACL____TextTransformation>;
  PositionalConstraint: string;
}

export interface ConnectionInput {
  Description?: string;
  ConnectionType: string;
  MatchCriteria?: Array<string>;
  PhysicalConnectionRequirements?: PhysicalConnectionRequirements;
  ConnectionProperties?: any;
  Name?: string;
}

export interface HostedZoneConfig {
  Comment?: string;
}

export interface NetworkFrameworkConfiguration {
  NetworkFabricConfiguration?: NetworkFabricConfiguration;
}

export interface AwsCloudMapInstanceAttribute {
  Value: string;
  Key: string;
}

export interface DestinationFlowConfig {
  ConnectorType: string;
  ConnectorProfileName?: string;
  DestinationConnectorProperties: DestinationConnectorProperties;
}

export interface AWS_SSM_MaintenanceWindowTask____LoggingInfo {
  S3Bucket: string;
  Region: string;
  S3Prefix?: string;
}

export interface AWS_Greengrass_ResourceDefinition____SecretsManagerSecretResourceData {
  ARN: string;
  AdditionalStagingLabelsToDownload?: Array<string>;
}

export interface AWS_SageMaker_Domain____JupyterServerAppSettings {
  DefaultResourceSpec?: AWS_SageMaker_Domain____ResourceSpec;
}

export interface StackInstances {
  DeploymentTargets: DeploymentTargets;
  Regions: Array<string>;
  ParameterOverrides?: Array<AWS_CloudFormation_StackSet____Parameter>;
}

export interface AWS_ManagedBlockchain_Member____NetworkConfiguration {
  Description?: string;
  FrameworkVersion: string;
  VotingPolicy: VotingPolicy;
  Framework: string;
  Name: string;
  NetworkFrameworkConfiguration?: NetworkFrameworkConfiguration;
}

export interface AWS_SageMaker_Domain____UserSettings {
  ExecutionRole?: string;
  JupyterServerAppSettings?: AWS_SageMaker_Domain____JupyterServerAppSettings;
  KernelGatewayAppSettings?: AWS_SageMaker_Domain____KernelGatewayAppSettings;
  SecurityGroups?: Array<string>;
  SharingSettings?: AWS_SageMaker_Domain____SharingSettings;
}

export interface DatadogSourceProperties {
  Object: string;
}

export interface AuditCheckConfiguration {
  Enabled?: boolean;
}

export interface MongoDbSettings {
  Port?: number;
  ExtractDocId?: string;
  DatabaseName?: string;
  AuthSource?: string;
  AuthMechanism?: string;
  Username?: string;
  DocsToInvestigate?: string;
  ServerName?: string;
  SecretsManagerSecretId?: string;
  AuthType?: string;
  SecretsManagerAccessRoleArn?: string;
  Password?: string;
  NestingLevel?: string;
}

export interface AWS_SSM_MaintenanceWindowTask____Target {
  Values: Array<string>;
  Key: string;
}

export interface FirewallRule {
  FirewallDomainListId: string;
  Priority: number;
  Action: string;
  BlockResponse?: string;
  BlockOverrideDomain?: string;
  BlockOverrideDnsType?: string;
  BlockOverrideTtl?: number;
}

export interface EFSVolumeConfiguration {
  FilesystemId: string;
  RootDirectory?: string;
  TransitEncryption?: string;
  TransitEncryptionPort?: number;
  AuthorizationConfig?: any;
}

export interface QueryStringConfig {
  Values?: Array<QueryStringKeyValue>;
}

export interface PolicyInformation {
  CertPolicyId: string;
  PolicyQualifiers?: Array<PolicyQualifierInfo>;
}

export interface PathPatternConfig {
  Values?: Array<string>;
}

export interface HeaderMatchMethod {
  Suffix?: string;
  Regex?: string;
  Exact?: string;
  Prefix?: string;
  Range?: MatchRange;
}

export interface ModelBiasBaselineConfig {
  BaseliningJobName?: string;
  ConstraintsResource?: AWS_SageMaker_ModelBiasJobDefinition____ConstraintsResource;
}

export interface OnPremisesTagSetListObject {
  OnPremisesTagGroup?: Array<AWS_CodeDeploy_DeploymentGroup____TagFilter>;
}

export interface AWS_SNS_Topic____Subscription {
  Endpoint: string;
  Protocol: string;
}

export interface PropertyGroup {
  PropertyMap?: any;
  PropertyGroupId?: string;
}

export interface EdgeOutputConfig {
  S3OutputLocation: string;
  KmsKeyId?: string;
}

export interface AWS_KinesisAnalytics_Application____Input {
  NamePrefix: string;
  InputSchema: AWS_KinesisAnalytics_Application____InputSchema;
  KinesisStreamsInput?: AWS_KinesisAnalytics_Application____KinesisStreamsInput;
  KinesisFirehoseInput?: AWS_KinesisAnalytics_Application____KinesisFirehoseInput;
  InputProcessingConfiguration?: AWS_KinesisAnalytics_Application____InputProcessingConfiguration;
  InputParallelism?: AWS_KinesisAnalytics_Application____InputParallelism;
}

export interface ProcessorFeature {
  Name?: string;
  Value?: string;
}

export interface AWS_QuickSight_Dashboard____ResourcePermission {
  Actions: Array<string>;
  Principal: string;
}

export interface SseKmsEncryptedObjects {
  Status: string;
}

export interface AWS_LookoutMetrics_AnomalyDetector____VpcConfiguration {
  SubnetIdList: Array<string>;
  SecurityGroupIdList: Array<string>;
}

export interface AWS_ApplicationAutoScaling_ScalingPolicy____PredefinedMetricSpecification {
  PredefinedMetricType: string;
  ResourceLabel?: string;
}

export interface VirtualGatewayTlsValidationContextFileTrust {
  CertificateChain: string;
}

export interface QueueConfiguration {
  Event: string;
  Filter?: NotificationFilter;
  Queue: string;
}

export interface AWS_ImageBuilder_ContainerRecipe____ComponentConfiguration {
  ComponentArn?: string;
}

export interface WebhookFilterRule {
  JsonPath: string;
  MatchEquals?: string;
}

export interface AWS_MSK_Cluster____S3 {
  Bucket?: string;
  Enabled: boolean;
  Prefix?: string;
}

export interface PhysicalConnectionRequirements {
  AvailabilityZone?: string;
  SecurityGroupIdList?: Array<string>;
  SubnetId?: string;
}

export interface LoadBalancerAttribute {
  Key?: string;
  Value?: string;
}

export interface AWS_EC2_LaunchTemplate____ElasticGpuSpecification {
  Type?: string;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____RecordFormat {
  MappingParameters?: AWS_KinesisAnalytics_ApplicationReferenceDataSource____MappingParameters;
  RecordFormatType: string;
}

export interface AWS_EC2_NetworkInterface____PrivateIpAddressSpecification {
  Primary: boolean;
  PrivateIpAddress: string;
}

export interface AWS_AppSync_FunctionConfiguration____SyncConfig {
  ConflictHandler?: string;
  ConflictDetection: string;
  LambdaConflictHandlerConfig?: AWS_AppSync_FunctionConfiguration____LambdaConflictHandlerConfig;
}

export interface GitSubmodulesConfig {
  FetchSubmodules: boolean;
}

export interface GatewayRouteSpec {
  HttpRoute?: HttpGatewayRoute;
  Http2Route?: HttpGatewayRoute;
  GrpcRoute?: GrpcGatewayRoute;
}

export interface Schema {
  SchemaArn?: string;
  SchemaName?: string;
  RegistryName?: string;
}

export interface LambdaAction {
  FunctionArn?: string;
}

export interface FileFormatConfiguration {
  ParquetConfiguration?: ParquetConfiguration;
  JsonConfiguration?: JsonConfiguration;
}

export interface ModelBiasJobInput {
  EndpointInput: AWS_SageMaker_ModelBiasJobDefinition____EndpointInput;
  GroundTruthS3Input: AWS_SageMaker_ModelBiasJobDefinition____MonitoringGroundTruthS3Input;
}

export interface ColumnWildcard {
  ExcludedColumnNames?: Array<string>;
}

export interface LogDestinationConfig {
  LogType: string;
  LogDestinationType: string;
  LogDestination: Record<string, string>;
}

export interface AnalysisAclRule {
  Cidr?: string;
  Egress?: boolean;
  PortRange?: AWS_EC2_NetworkInsightsAnalysis____PortRange;
  Protocol?: string;
  RuleAction?: string;
  RuleNumber?: number;
}

export interface OnPremConfig {
  AgentArns: Array<string>;
}

export interface AWS_KinesisAnalyticsV2_Application____MappingParameters {
  JSONMappingParameters?: AWS_KinesisAnalyticsV2_Application____JSONMappingParameters;
  CSVMappingParameters?: AWS_KinesisAnalyticsV2_Application____CSVMappingParameters;
}

export interface AWS_ElasticLoadBalancingV2_Listener____ForwardConfig {
  TargetGroupStickinessConfig?: AWS_ElasticLoadBalancingV2_Listener____TargetGroupStickinessConfig;
  TargetGroups?: Array<AWS_ElasticLoadBalancingV2_Listener____TargetGroupTuple>;
}

export interface AlternatePathHint {
  ComponentId?: string;
  ComponentArn?: string;
}

export interface MachineLearningDetectionConfig {
  ConfidenceLevel?: string;
}

export interface ObjectLockConfiguration {
  ObjectLockEnabled?: string;
  Rule?: ObjectLockRule;
}

export interface SchemaVersion {
  IsLatest?: boolean;
  VersionNumber?: number;
}

export interface DeploymentStyle {
  DeploymentOption?: string;
  DeploymentType?: string;
}

export interface DeploymentController {
  Type?: string;
}

export interface AdminCreateUserConfig {
  InviteMessageTemplate?: InviteMessageTemplate;
  UnusedAccountValidityDays?: number;
  AllowAdminCreateUserOnly?: boolean;
}

export interface AWS_EC2_Instance____Ebs {
  DeleteOnTermination?: boolean;
  Encrypted?: boolean;
  Iops?: number;
  KmsKeyId?: string;
  SnapshotId?: string;
  VolumeSize?: number;
  VolumeType?: string;
}

export interface AWS_EventSchemas_Discoverer____TagsEntry {
  Value: string;
  Key: string;
}

export interface PortOverride {
  ListenerPort: number;
  EndpointPort: number;
}

export interface CreateColumnsOperation {
  Columns: Array<CalculatedColumn>;
}

export interface ModelExplainabilityAppSpecification {
  ImageUri: string;
  ConfigUri: string;
  Environment?: AWS_SageMaker_ModelExplainabilityJobDefinition____Environment;
}

export interface AggregationConfig {
  AggregationType?: string;
}

export interface SystemControl {
  Namespace?: string;
  Value?: string;
}

export interface AWS_ApplicationAutoScaling_ScalingPolicy____CustomizedMetricSpecification {
  Dimensions?: Array<AWS_ApplicationAutoScaling_ScalingPolicy____MetricDimension>;
  MetricName: string;
  Namespace: string;
  Statistic: string;
  Unit?: string;
}

export interface DatasetContentDeliveryRule {
  Destination: DatasetContentDeliveryRuleDestination;
  EntryName?: string;
}

export interface ClientConnectOptions {
  LambdaFunctionArn?: string;
  Enabled: boolean;
}

export interface AWS_EC2_LaunchTemplate____TagSpecification {
  ResourceType?: string;
  Tags?: Array<Tag>;
}

export interface AWS_SageMaker_Model____VpcConfig {
  Subnets: Array<string>;
  SecurityGroupIds: Array<string>;
}

export interface DataflowEndpoint {
  Name?: string;
  Address?: SocketAddress;
  Mtu?: number;
}

export interface ActivityMetrics {
  IsEnabled?: boolean;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____MonitoringResources {
  ClusterConfig: AWS_SageMaker_ModelBiasJobDefinition____ClusterConfig;
}

export interface AnalysisSourceTemplate {
  DataSetReferences: Array<AWS_QuickSight_Analysis____DataSetReference>;
  Arn: string;
}

export interface AWS_OpsWorks_Instance____BlockDeviceMapping {
  DeviceName?: string;
  Ebs?: AWS_OpsWorks_Instance____EbsBlockDevice;
  NoDevice?: string;
  VirtualName?: string;
}

export interface SnowflakeParameters {
  Warehouse: string;
  Database: string;
  Host: string;
}

export interface LoggingConfig {
  LogGroupName?: string;
  LogRoleArn?: string;
}

export interface RouteSpec {
  HttpRoute?: HttpRoute;
  Priority?: number;
  Http2Route?: HttpRoute;
  GrpcRoute?: GrpcRoute;
  TcpRoute?: TcpRoute;
}

export interface BucketLevel {
  ActivityMetrics?: ActivityMetrics;
  PrefixLevel?: PrefixLevel;
}

export interface LogList {
  Audit?: boolean;
  General?: boolean;
}

export interface EventSource {
  Type: string;
  Parameters?: EventParameters;
}

export interface PipelineObject {
  Fields: Array<Field>;
  Id: string;
  Name: string;
}

export interface AWS_ApiGateway_DocumentationPart____Location {
  Method?: string;
  Name?: string;
  Path?: string;
  StatusCode?: string;
  Type?: string;
}

export interface NoDevice {}

export interface ExperimentTemplateStopCondition {
  Source: string;
  Value?: string;
}

export interface AWS_SageMaker_AppImageConfig____FileSystemConfig {
  DefaultGid?: number;
  DefaultUid?: number;
  MountPath?: string;
}

export interface AWS_IAM_Role____Policy {
  PolicyDocument: any;
  PolicyName: string;
}

export interface AWS_KinesisAnalyticsV2_Application____InputParallelism {
  Count?: number;
}

export interface AWS_Batch_JobDefinition____Environment {
  Value?: string;
  Name?: string;
}

export interface AWS_FraudDetector_Detector____Label {
  Arn?: string;
  Inline?: boolean;
  Name?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface ScheduledTriggerProperties {
  ScheduleExpression: string;
  DataPullMode?: string;
  ScheduleStartTime?: number;
  ScheduleEndTime?: number;
  TimeZone?: string;
}

export interface AWS_EMR_Cluster____CloudWatchAlarmDefinition {
  ComparisonOperator: string;
  Dimensions?: Array<AWS_EMR_Cluster____MetricDimension>;
  EvaluationPeriods?: number;
  MetricName: string;
  Namespace?: string;
  Period: number;
  Statistic?: string;
  Threshold: number;
  Unit?: string;
}

export interface AWS_Glue_Crawler____Schedule {
  ScheduleExpression?: string;
}

export interface DestinationConnectorProperties {
  Redshift?: RedshiftDestinationProperties;
  S3?: S3DestinationProperties;
  Salesforce?: SalesforceDestinationProperties;
  Snowflake?: SnowflakeDestinationProperties;
  EventBridge?: EventBridgeDestinationProperties;
  Upsolver?: UpsolverDestinationProperties;
  LookoutMetrics?: LookoutMetricsDestinationProperties;
}

export interface AWS_IoTEvents_DetectorModel____Firehose {
  DeliveryStreamName: string;
  Payload?: Payload;
  Separator?: string;
}

export interface AWS_EKS_FargateProfile____Label {
  Key: string;
  Value: string;
}

export interface AWS_ECS_TaskSet____NetworkConfiguration {
  AwsVpcConfiguration?: AWS_ECS_TaskSet____AwsVpcConfiguration;
}

export interface DatabaseResource {
  CatalogId?: string;
  Name?: string;
}

export interface S3Origin {
  DomainName: string;
  OriginAccessIdentity: string;
}

export interface StackConfigurationManager {
  Name?: string;
  Version?: string;
}

export interface LambdaVolumeMount {
  SourcePath?: string;
  DestinationPath?: string;
  Permission?: string;
  AddGroupOwner?: boolean;
}

export interface AWS_CodeBuild_Project____VpcConfig {
  Subnets?: Array<string>;
  VpcId?: string;
  SecurityGroupIds?: Array<string>;
}

export interface SmsConfiguration {
  ExternalId?: string;
  SnsCallerArn?: string;
}

export interface ClusterSettings {
  Name?: string;
  Value?: string;
}

export interface BucketsAndRegions {
  Buckets?: Array<string>;
  Regions?: Array<string>;
}

export interface LocationCapacity {
  DesiredEC2Instances: number;
  MinSize: number;
  MaxSize: number;
}

export interface ConnectorOperator {
  Amplitude?: string;
  Datadog?: string;
  Dynatrace?: string;
  GoogleAnalytics?: string;
  InforNexus?: string;
  Marketo?: string;
  S3?: string;
  Salesforce?: string;
  ServiceNow?: string;
  Singular?: string;
  Slack?: string;
  Trendmicro?: string;
  Veeva?: string;
  Zendesk?: string;
}

export interface AWS_WAFv2_RuleGroup____LabelMatchStatement {
  Scope: string;
  Key: string;
}

export interface AWS_SageMaker_DataQualityJobDefinition____ConstraintsResource {
  S3Uri?: string;
}

export interface DynamoDBAction {
  TableName: string;
  PayloadField?: string;
  RangeKeyField?: string;
  HashKeyField: string;
  RangeKeyValue?: string;
  RangeKeyType?: string;
  HashKeyType?: string;
  HashKeyValue: string;
  RoleArn: string;
}

export interface HiveJsonSerDe {
  TimestampFormats?: Array<string>;
}

export interface TargetDescription {
  AvailabilityZone?: string;
  Id: string;
  Port?: number;
}

export interface PlacementConstraint {
  Expression?: string;
  Type: string;
}

export interface Header {
  Protocol: string;
  Source: string;
  SourcePort: string;
  Direction: string;
  Destination: string;
  DestinationPort: string;
}

export interface AWS_EC2_Instance____CreditSpecification {
  CPUCredits?: string;
}

export interface CachePolicyConfig {
  Comment?: string;
  DefaultTTL: number;
  MaxTTL: number;
  MinTTL: number;
  Name: string;
  ParametersInCacheKeyAndForwardedToOrigin: ParametersInCacheKeyAndForwardedToOrigin;
}

export interface AWS_WAFRegional_SizeConstraintSet____SizeConstraint {
  ComparisonOperator: string;
  Size: number;
  TextTransformation: string;
  FieldToMatch: AWS_WAFRegional_SizeConstraintSet____FieldToMatch;
}

export interface EventParameters {
  EventType: string;
  SnapshotOwner: Array<string>;
  DescriptionRegex?: string;
}

export interface ComponentMonitoringSetting {
  ComponentName?: string;
  ComponentARN?: string;
  Tier?: string;
  ComponentConfigurationMode?: string;
  DefaultOverwriteComponentConfiguration?: AWS_ApplicationInsights_Application____ComponentConfiguration;
  CustomComponentConfiguration?: AWS_ApplicationInsights_Application____ComponentConfiguration;
}

export interface AWS_ECR_Repository____LifecyclePolicy {
  LifecyclePolicyText?: string;
  RegistryId?: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationOutput____KinesisFirehoseOutput {
  ResourceARN: string;
}

export interface SnsChannelConfig {
  TopicArn?: string;
}

export interface ResponseParameterList {
  ResponseParameters?: Array<ResponseParameter>;
}

export interface QueryLoggingConfig {
  CloudWatchLogsLogGroupArn: string;
}

export interface AWS_Lambda_Function____Code {
  ImageUri?: string;
  S3Bucket?: string;
  S3Key?: string;
  S3ObjectVersion?: string;
  ZipFile?: string;
}

export interface ListenerTlsValidationContext {
  SubjectAlternativeNames?: AWS_AppMesh_VirtualNode____SubjectAlternativeNames;
  Trust: ListenerTlsValidationContextTrust;
}

export interface TargetCapacitySpecificationRequest {
  DefaultTargetCapacityType?: string;
  TotalTargetCapacity: number;
  OnDemandTargetCapacity?: number;
  SpotTargetCapacity?: number;
}

export interface Processor {
  Parameters?: Array<ProcessorParameter>;
  Type: string;
}

export interface LambdaFunctionRecipeSource {
  LambdaArn?: string;
  ComponentName?: string;
  ComponentVersion?: string;
  ComponentPlatforms?: Array<ComponentPlatform>;
  ComponentDependencies?: Record<string, ComponentDependencyRequirement>;
  ComponentLambdaParameters?: LambdaExecutionParameters;
}

export interface EC2TagFilter {
  Key?: string;
  Type?: string;
  Value?: string;
}

export interface VirtualGatewayHttp2ConnectionPool {
  MaxRequests: number;
}

export interface AWS_WAFv2_WebACL____ForwardedIPConfiguration {
  HeaderName: string;
  FallbackBehavior: string;
}

export interface AWS_SageMaker_Domain____CustomImage {
  AppImageConfigName: string;
  ImageName: string;
  ImageVersionNumber?: number;
}

export interface AWS_KinesisAnalyticsV2_ApplicationOutput____KinesisStreamsOutput {
  ResourceARN: string;
}

export interface LogPattern {
  PatternName: string;
  Pattern: string;
  Rank: number;
}

export interface DataCatalogEncryptionSettings {
  ConnectionPasswordEncryption?: ConnectionPasswordEncryption;
  EncryptionAtRest?: AWS_Glue_DataCatalogEncryptionSettings____EncryptionAtRest;
}

export interface AWS_ECS_TaskSet____ServiceRegistry {
  ContainerName?: string;
  ContainerPort?: number;
  Port?: number;
  RegistryArn?: string;
}

export interface ProvisioningParameter {
  Key: string;
  Value: string;
}

export interface AWS_DataBrew_Job____S3Location {
  Bucket: string;
  Key?: string;
}

export interface PointInTimeRecoverySpecification {
  PointInTimeRecoveryEnabled?: boolean;
}

export interface AWS_IoTAnalytics_Datastore____ServiceManagedS3 {}

export interface FlinkApplicationConfiguration {
  CheckpointConfiguration?: CheckpointConfiguration;
  ParallelismConfiguration?: ParallelismConfiguration;
  MonitoringConfiguration?: MonitoringConfiguration;
}

export interface AWS_ApiGatewayV2_Route____ParameterConstraints {
  Required: boolean;
}

export interface ProvisionalConfiguration {
  MaxTimeToLiveInMinutes: number;
}

export interface AutoDeployment {
  Enabled?: boolean;
  RetainStacksOnAccountRemoval?: boolean;
}

export interface ClearTimer {
  TimerName: string;
}

export interface AWS_AppConfig_DeploymentStrategy____Tags {
  Value?: string;
  Key?: string;
}

export interface Explanation {
  Acl?: AnalysisComponent;
  AclRule?: AnalysisAclRule;
  Address?: string;
  Addresses?: Array<string>;
  AttachedTo?: AnalysisComponent;
  AvailabilityZones?: Array<string>;
  Cidrs?: Array<string>;
  Component?: AnalysisComponent;
  CustomerGateway?: AnalysisComponent;
  Destination?: AnalysisComponent;
  DestinationVpc?: AnalysisComponent;
  Direction?: string;
  ExplanationCode?: string;
  IngressRouteTable?: AnalysisComponent;
  InternetGateway?: AnalysisComponent;
  LoadBalancerArn?: string;
  ClassicLoadBalancerListener?: AnalysisLoadBalancerListener;
  LoadBalancerListenerPort?: number;
  LoadBalancerTarget?: AnalysisLoadBalancerTarget;
  LoadBalancerTargetGroup?: AnalysisComponent;
  LoadBalancerTargetGroups?: Array<AnalysisComponent>;
  LoadBalancerTargetPort?: number;
  ElasticLoadBalancerListener?: AnalysisComponent;
  MissingComponent?: string;
  NatGateway?: AnalysisComponent;
  NetworkInterface?: AnalysisComponent;
  PacketField?: string;
  VpcPeeringConnection?: AnalysisComponent;
  Port?: number;
  PortRanges?: Array<AWS_EC2_NetworkInsightsAnalysis____PortRange>;
  PrefixList?: AnalysisComponent;
  Protocols?: Array<string>;
  RouteTableRoute?: AnalysisRouteTableRoute;
  RouteTable?: AnalysisComponent;
  SecurityGroup?: AnalysisComponent;
  SecurityGroupRule?: AnalysisSecurityGroupRule;
  SecurityGroups?: Array<AnalysisComponent>;
  SourceVpc?: AnalysisComponent;
  State?: string;
  Subnet?: AnalysisComponent;
  SubnetRouteTable?: AnalysisComponent;
  Vpc?: AnalysisComponent;
  vpcEndpoint?: AnalysisComponent;
  VpnConnection?: AnalysisComponent;
  VpnGateway?: AnalysisComponent;
}

export interface ZendeskSourceProperties {
  Object: string;
}

export interface RdsDbInstance {
  DbPassword: string;
  DbUser: string;
  RdsDbInstanceArn: string;
}

export interface AWS_WAF_ByteMatchSet____FieldToMatch {
  Data?: string;
  Type: string;
}

export interface AWS_S3Outposts_AccessPoint____VpcConfiguration {
  VpcId?: string;
}

export interface AccelerateConfiguration {
  AccelerationStatus: string;
}

export interface AWS_IoT_SecurityProfile____MetricDimension {
  DimensionName: string;
  Operator?: string;
}

export interface AWS_Glue_Trigger____Condition {
  CrawlerName?: string;
  State?: string;
  CrawlState?: string;
  LogicalOperator?: string;
  JobName?: string;
}

export interface MetricValue {
  Count?: string;
  Cidrs?: Array<string>;
  Ports?: Array<number>;
  Number?: number;
  Numbers?: Array<number>;
  Strings?: Array<string>;
}

export interface BatchRetryStrategy {
  Attempts?: number;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____CSVMappingParameters {
  RecordRowDelimiter: string;
  RecordColumnDelimiter: string;
}

export interface SignatureValidityPeriod {
  Value?: number;
  Type?: string;
}

export interface DistributionConfig {
  Aliases?: Array<string>;
  CNAMEs?: Array<string>;
  CacheBehaviors?: Array<CacheBehavior>;
  Comment?: string;
  CustomErrorResponses?: Array<CustomErrorResponse>;
  CustomOrigin?: LegacyCustomOrigin;
  DefaultCacheBehavior?: DefaultCacheBehavior;
  DefaultRootObject?: string;
  Enabled: boolean;
  HttpVersion?: string;
  IPV6Enabled?: boolean;
  Logging?: AWS_CloudFront_Distribution____Logging;
  OriginGroups?: OriginGroups;
  Origins?: Array<Origin>;
  PriceClass?: string;
  Restrictions?: Restrictions;
  S3Origin?: LegacyS3Origin;
  ViewerCertificate?: ViewerCertificate;
  WebACLId?: string;
}

export interface AWS_NetworkFirewall_RuleGroup____Dimension {
  Value: string;
}

export interface DeploymentTargets {
  Accounts?: Array<string>;
  OrganizationalUnitIds?: Array<string>;
}

export interface SamplingRuleUpdate {
  Attributes?: Record<string, string>;
  FixedRate?: number;
  Host?: string;
  HTTPMethod?: string;
  Priority?: number;
  ReservoirSize?: number;
  ResourceARN?: string;
  RuleARN?: string;
  RuleName?: string;
  ServiceName?: string;
  ServiceType?: string;
  URLPath?: string;
}

export interface AWS_EMR_Cluster____KeyValue {
  Key?: string;
  Value?: string;
}

export interface AWS_EC2_SpotFleet____LaunchTemplateOverrides {
  AvailabilityZone?: string;
  InstanceType?: string;
  Priority?: number;
  SpotPrice?: string;
  SubnetId?: string;
  WeightedCapacity?: number;
}

export interface MetricDataQuery {
  Expression?: string;
  Id: string;
  Label?: string;
  MetricStat?: MetricStat;
  Period?: number;
  ReturnData?: boolean;
}

export interface LogPatternSet {
  PatternSetName: string;
  LogPatterns: Array<LogPattern>;
}

export interface AWS_S3_StorageLens____DataExport {
  S3BucketDestination: S3BucketDestination;
}

export interface AWS_KinesisAnalytics_Application____JSONMappingParameters {
  RecordRowPath: string;
}

export interface ConsumptionConfiguration {
  RenewType?: string;
  ProvisionalConfiguration?: ProvisionalConfiguration;
  BorrowConfiguration?: BorrowConfiguration;
}

export interface AWS_ApplicationInsights_Application____Alarm {
  AlarmName: string;
  Severity?: string;
}

export interface KinesisStreamSpecification {
  StreamArn: string;
}

export interface SecondaryInput {
  S3InputDefinition?: AWS_DataBrew_Recipe____S3Location;
  DataCatalogInputDefinition?: AWS_DataBrew_Recipe____DataCatalogInputDefinition;
}

export interface SubscriptionDefinitionVersion {
  Subscriptions: Array<AWS_Greengrass_SubscriptionDefinition____Subscription>;
}

export interface AnalysisLoadBalancerListener {
  InstancePort?: number;
  LoadBalancerPort?: number;
}

export interface AWS_AppMesh_VirtualNode____TcpTimeout {
  Idle?: AWS_AppMesh_VirtualNode____Duration;
}

export interface IssuerData {
  Name: string;
  SignKey?: string;
}

export interface DatabaseIdentifier {
  DatabaseName?: string;
  CatalogId?: string;
}

export interface AWS_WAFv2_WebACL____OrStatement {
  Statements: Array<AWS_WAFv2_WebACL____Statement>;
}

export interface VolumesHost {
  SourcePath?: string;
}

export interface GoogleAnalyticsConnectorProfileCredentials {
  ClientId: string;
  ClientSecret: string;
  AccessToken?: string;
  RefreshToken?: string;
  ConnectorOAuthRequest?: ConnectorOAuthRequest;
}

export interface AWS_Amplify_App____EnvironmentVariable {
  Value: string;
  Name: string;
}

export interface SalesforceDestinationProperties {
  Object: string;
  ErrorHandlingConfig?: ErrorHandlingConfig;
  IdFieldNames?: Array<string>;
  WriteOperationType?: string;
}

export interface AWS_IoTAnalytics_Dataset____Action {
  ActionName: string;
  ContainerAction?: ContainerAction;
  QueryAction?: QueryAction;
}

export interface LateDataRuleConfiguration {
  DeltaTimeSessionWindowConfiguration?: DeltaTimeSessionWindowConfiguration;
}

export interface AWS_WAFv2_RuleGroup____RuleAction {
  Allow?: any;
  Block?: any;
  Count?: any;
}

export interface AWS_EC2_LaunchTemplate____Ebs {
  SnapshotId?: string;
  VolumeType?: string;
  KmsKeyId?: string;
  Encrypted?: boolean;
  Throughput?: number;
  Iops?: number;
  VolumeSize?: number;
  DeleteOnTermination?: boolean;
}

export interface AccountTakeoverActionType {
  Notify: boolean;
  EventAction: string;
}

export interface ComputeEnvironmentOrder {
  ComputeEnvironment: string;
  Order: number;
}

export interface SubDomainSetting {
  Prefix: string;
  BranchName: string;
}

export interface IntelligentTieringConfiguration {
  Id: string;
  Prefix?: string;
  Status: string;
  TagFilters?: Array<AWS_S3_Bucket____TagFilter>;
  Tierings: Array<Tiering>;
}

export interface AliasRoutingConfiguration {
  AdditionalVersionWeights: Array<VersionWeight>;
}

export interface AWS_Greengrass_ResourceDefinition____ResourceDownloadOwnerSetting {
  GroupOwner: string;
  GroupPermission: string;
}

export interface AWS_SageMaker_MonitoringSchedule____ConstraintsResource {
  S3Uri?: string;
}

export interface AWS_S3_Bucket____AbortIncompleteMultipartUpload {
  DaysAfterInitiation: number;
}

export interface ContainerAction {
  Variables?: Array<Variable>;
  ExecutionRoleArn: string;
  Image: string;
  ResourceConfiguration: ResourceConfiguration;
}

export interface AWS_KinesisAnalyticsV2_Application____Input {
  NamePrefix: string;
  InputSchema: AWS_KinesisAnalyticsV2_Application____InputSchema;
  KinesisStreamsInput?: AWS_KinesisAnalyticsV2_Application____KinesisStreamsInput;
  KinesisFirehoseInput?: AWS_KinesisAnalyticsV2_Application____KinesisFirehoseInput;
  InputProcessingConfiguration?: AWS_KinesisAnalyticsV2_Application____InputProcessingConfiguration;
  InputParallelism?: AWS_KinesisAnalyticsV2_Application____InputParallelism;
}

export interface Query {
  ResourceTypeFilters?: Array<string>;
  StackIdentifier?: string;
  TagFilters?: Array<AWS_ResourceGroups_Group____TagFilter>;
}

export interface OutputArtifact {
  Name: string;
}

export interface LegacyS3Origin {
  DNSName: string;
  OriginAccessIdentity?: string;
}

export interface DataFormatConversionConfiguration {
  Enabled?: boolean;
  InputFormatConfiguration?: InputFormatConfiguration;
  OutputFormatConfiguration?: OutputFormatConfiguration;
  SchemaConfiguration?: SchemaConfiguration;
}

export interface ApplicationSnapshotConfiguration {
  SnapshotsEnabled: boolean;
}

export interface AWS_Amplify_Branch____BasicAuthConfig {
  Username: string;
  EnableBasicAuth?: boolean;
  Password: string;
}

export interface AWS_KinesisAnalyticsV2_Application____KinesisFirehoseInput {
  ResourceARN: string;
}

export interface SslProperties {
  DisableSsl?: boolean;
}

export interface RoleMapping {
  Type: string;
  AmbiguousRoleResolution?: string;
  RulesConfiguration?: RulesConfigurationType;
  IdentityProvider?: string;
}

export interface OnPremisesTagSet {
  OnPremisesTagSetList?: Array<OnPremisesTagSetListObject>;
}

export interface AntennaDownlinkConfig {
  SpectrumConfig?: SpectrumConfig;
}

export interface AWS_WAFv2_WebACL____Label {
  Name: string;
}

export interface SimulationSoftwareSuite {
  Version: string;
  Name: string;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____LocalDeviceResourceData {
  SourcePath: string;
  GroupOwnerSetting?: AWS_Greengrass_ResourceDefinitionVersion____GroupOwnerSetting;
}

export interface AWS_DataBrew_Recipe____Action {
  Operation: string;
}

export interface IotAnalyticsAction {
  RoleArn: string;
  ChannelName: string;
  BatchMode?: boolean;
}

export interface PhysicalTable {
  RelationalTable?: RelationalTable;
  CustomSql?: CustomSql;
  S3Source?: S3Source;
}

export interface Backend {
  VirtualService?: VirtualServiceBackend;
}

export interface OriginCustomHeader {
  HeaderName: string;
  HeaderValue: string;
}

export interface VirtualGatewaySpec {
  Logging?: VirtualGatewayLogging;
  Listeners: Array<VirtualGatewayListener>;
  BackendDefaults?: VirtualGatewayBackendDefaults;
}

export interface AWS_GameLift_Build____S3Location {
  Bucket: string;
  Key: string;
  ObjectVersion?: string;
  RoleArn: string;
}

export interface AWS_EMR_Cluster____VolumeSpecification {
  Iops?: number;
  SizeInGB: number;
  VolumeType: string;
}

export interface OperationPreferences {
  FailureToleranceCount?: number;
  FailureTolerancePercentage?: number;
  MaxConcurrentCount?: number;
  MaxConcurrentPercentage?: number;
  RegionOrder?: Array<string>;
  RegionConcurrencyType?: string;
}

export interface FindingsFilterListItem {
  Id?: string;
  Name?: string;
}

export interface DeleteMarkerReplication {
  Status?: string;
}

export interface LateDataRule {
  RuleConfiguration: LateDataRuleConfiguration;
  RuleName?: string;
}

export interface CustomHTTPHeader {
  Name: string;
  Value: string;
}

export interface TableWildcard {}

export interface AwsOrg {
  Arn: string;
}

export interface ModelExplainabilityJobInput {
  EndpointInput: AWS_SageMaker_ModelExplainabilityJobDefinition____EndpointInput;
}

export interface EphemeralStorage {
  SizeInGiB?: number;
}

export interface AWS_ImageBuilder_InfrastructureConfiguration____Logging {
  S3Logs?: S3Logs;
}

export interface AWS_S3_Bucket____PublicAccessBlockConfiguration {
  BlockPublicAcls?: boolean;
  BlockPublicPolicy?: boolean;
  IgnorePublicAcls?: boolean;
  RestrictPublicBuckets?: boolean;
}

export interface AWS_WAFv2_WebACL____RegexPatternSetReferenceStatement {
  Arn: string;
  FieldToMatch: AWS_WAFv2_WebACL____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_WebACL____TextTransformation>;
}

export interface AWS_ACMPCA_CertificateAuthority____KeyUsage {
  DigitalSignature?: boolean;
  NonRepudiation?: boolean;
  KeyEncipherment?: boolean;
  DataEncipherment?: boolean;
  KeyAgreement?: boolean;
  KeyCertSign?: boolean;
  CRLSign?: boolean;
  EncipherOnly?: boolean;
  DecipherOnly?: boolean;
}

export interface AWS_ECR_ReplicationConfiguration____ReplicationDestination {
  Region: string;
  RegistryId: string;
}

export interface MonitoringExecutionSummary {
  CreationTime: string;
  EndpointName?: string;
  FailureReason?: string;
  LastModifiedTime: string;
  MonitoringExecutionStatus: string;
  MonitoringScheduleName: string;
  ProcessingJobArn?: string;
  ScheduledTime: string;
}

export type AWS_StepFunctions_StateMachine____Definition = undefined;

export interface ErrorHandlingConfig {
  FailOnFirstError?: boolean;
  BucketPrefix?: string;
  BucketName?: string;
}

export interface ReportExportConfig {
  S3Destination?: S3ReportExportConfig;
  ExportConfigType: string;
}

export interface MappingRule {
  MatchType: string;
  Value: string;
  Claim: string;
  RoleARN: string;
}

export interface IotEventsAction {
  InputName: string;
  RoleArn: string;
  MessageId?: string;
  BatchMode?: boolean;
}

export interface AWS_SageMaker_UserProfile____JupyterServerAppSettings {
  DefaultResourceSpec?: AWS_SageMaker_UserProfile____ResourceSpec;
}

export interface AuditNotificationTargetConfigurations {
  Sns?: AuditNotificationTarget;
}

export interface AWS_DLM_LifecyclePolicy____Action {
  CrossRegionCopy: Array<CrossRegionCopyAction>;
  Name: string;
}

export interface AWS_ElastiCache_ReplicationGroup____CloudWatchLogsDestinationDetails {
  LogGroup?: string;
}

export interface CognitoStreams {
  StreamingStatus?: string;
  StreamName?: string;
  RoleArn?: string;
}

export interface AWS_WAFv2_RuleGroup____Statement {
  ByteMatchStatement?: AWS_WAFv2_RuleGroup____ByteMatchStatement;
  SqliMatchStatement?: AWS_WAFv2_RuleGroup____SqliMatchStatement;
  XssMatchStatement?: AWS_WAFv2_RuleGroup____XssMatchStatement;
  SizeConstraintStatement?: AWS_WAFv2_RuleGroup____SizeConstraintStatement;
  GeoMatchStatement?: AWS_WAFv2_RuleGroup____GeoMatchStatement;
  IPSetReferenceStatement?: AWS_WAFv2_RuleGroup____IPSetReferenceStatement;
  RegexPatternSetReferenceStatement?: AWS_WAFv2_RuleGroup____RegexPatternSetReferenceStatement;
  RateBasedStatement?: AWS_WAFv2_RuleGroup____RateBasedStatement;
  AndStatement?: AWS_WAFv2_RuleGroup____AndStatement;
  OrStatement?: AWS_WAFv2_RuleGroup____OrStatement;
  NotStatement?: AWS_WAFv2_RuleGroup____NotStatement;
  LabelMatchStatement?: AWS_WAFv2_RuleGroup____LabelMatchStatement;
}

export interface AWS_KinesisAnalyticsV2_Application____InputSchema {
  RecordEncoding?: string;
  RecordColumns: Array<AWS_KinesisAnalyticsV2_Application____RecordColumn>;
  RecordFormat: AWS_KinesisAnalyticsV2_Application____RecordFormat;
}

export interface PartitionInput {
  Parameters?: any;
  StorageDescriptor?: AWS_Glue_Partition____StorageDescriptor;
  Values: Array<string>;
}

export interface AWS_CodeStar_GitHubRepository____S3 {
  ObjectVersion?: string;
  Bucket: string;
  Key: string;
}

export interface S3SourceProperties {
  BucketName: string;
  BucketPrefix: string;
}

export interface LabelSummary {
  Name?: string;
}

export interface KafkaSettings {
  Broker?: string;
  Topic?: string;
}

export interface ListenerTimeout {
  TCP?: AWS_AppMesh_VirtualNode____TcpTimeout;
  HTTP2?: AWS_AppMesh_VirtualNode____HttpTimeout;
  HTTP?: AWS_AppMesh_VirtualNode____HttpTimeout;
  GRPC?: AWS_AppMesh_VirtualNode____GrpcTimeout;
}

export interface AWS_MediaConnect_FlowOutput____Encryption {
  Algorithm: string;
  KeyType?: string;
  RoleArn: string;
  SecretArn: string;
}

export interface AWS_EMR_Cluster____InstanceFleetProvisioningSpecifications {
  OnDemandSpecification?: AWS_EMR_Cluster____OnDemandProvisioningSpecification;
  SpotSpecification?: AWS_EMR_Cluster____SpotProvisioningSpecification;
}

export interface AWS_IoTAnalytics_Datastore____RetentionPeriod {
  NumberOfDays?: number;
  Unlimited?: boolean;
}

export interface NodeGroupConfiguration {
  NodeGroupId?: string;
  PrimaryAvailabilityZone?: string;
  ReplicaAvailabilityZones?: Array<string>;
  ReplicaCount?: number;
  Slots?: string;
}

export interface RDSSourceConfig {
  DBInstanceIdentifier: string;
  DatabaseHost: string;
  DatabasePort: number;
  SecretManagerArn: string;
  DatabaseName: string;
  TableName: string;
  RoleArn: string;
  VpcConfiguration: AWS_LookoutMetrics_AnomalyDetector____VpcConfiguration;
}

export interface AWS_WAFv2_WebACL____IPSetForwardedIPConfiguration {
  HeaderName: string;
  FallbackBehavior: string;
  Position: string;
}

export interface AWS_Glue_Table____Column {
  Comment?: string;
  Type?: string;
  Name: string;
}

export interface State {
  OnEnter?: OnEnter;
  OnExit?: OnExit;
  OnInput?: OnInput;
  StateName: string;
}

export interface AWS_Glue_DataCatalogEncryptionSettings____EncryptionAtRest {
  CatalogEncryptionMode?: string;
  SseAwsKmsKeyId?: string;
}

export interface MaxAgeRule {
  DeleteSourceFromS3?: boolean;
  Enabled?: boolean;
  MaxAgeInDays?: number;
}

export interface CaptureOption {
  CaptureMode: string;
}

export interface ColumnDescription {
  Text?: string;
}

export interface AWS_EMR_InstanceGroupConfig____AutoScalingPolicy {
  Constraints: AWS_EMR_InstanceGroupConfig____ScalingConstraints;
  Rules: Array<AWS_EMR_InstanceGroupConfig____ScalingRule>;
}

export interface S3Parameters {
  ManifestFileLocation: ManifestFileLocation;
}

export interface AWS_ECR_ReplicationConfiguration____ReplicationRule {
  Destinations: Array<AWS_ECR_ReplicationConfiguration____ReplicationDestination>;
}

export interface KafkaAction {
  DestinationArn: string;
  Topic: string;
  Key?: string;
  Partition?: string;
  ClientProperties: Record<string, string>;
}

export interface TrafficRoutingConfig {
  Type: string;
  CanarySize?: CapacitySize;
  WaitIntervalInSeconds?: number;
}

export interface AWS_ApiGateway_Deployment____AccessLogSetting {
  DestinationArn?: string;
  Format?: string;
}

export interface DirectoryServiceAuthenticationRequest {
  DirectoryId: string;
}

export interface OutputFormatOptions {
  Csv?: CsvOutputOptions;
}

export interface ElasticFileSystemTag {
  Key: string;
  Value: string;
}

export interface SchemaChangePolicy {
  UpdateBehavior?: string;
  DeleteBehavior?: string;
}

export interface CsrExtensions {
  KeyUsage?: AWS_ACMPCA_CertificateAuthority____KeyUsage;
  SubjectInformationAccess?: Array<AccessDescription>;
}

export interface StringAttributeConstraints {
  MinLength?: string;
  MaxLength?: string;
}

export interface StatelessRuleGroupReference {
  ResourceArn: string;
  Priority: number;
}

export interface VirtualGatewayTlsValidationContext {
  SubjectAlternativeNames?: AWS_AppMesh_VirtualGateway____SubjectAlternativeNames;
  Trust: VirtualGatewayTlsValidationContextTrust;
}

export interface AWS_AppMesh_VirtualNode____PortMapping {
  Port: number;
  Protocol: string;
}

export interface Artifacts {
  Path?: string;
  Type: string;
  ArtifactIdentifier?: string;
  OverrideArtifactName?: boolean;
  Packaging?: string;
  EncryptionDisabled?: boolean;
  Location?: string;
  Name?: string;
  NamespaceType?: string;
}

export interface OriginGroup {
  FailoverCriteria: OriginGroupFailoverCriteria;
  Id: string;
  Members: OriginGroupMembers;
}

export interface AWS_WAFv2_WebACL____CustomResponseBody {
  ContentType: string;
  Content: string;
}

export interface CsvOutputOptions {
  Delimiter?: string;
}

export interface VerificationMessageTemplate {
  EmailMessageByLink?: string;
  EmailMessage?: string;
  SmsMessage?: string;
  EmailSubject?: string;
  DefaultEmailOption?: string;
  EmailSubjectByLink?: string;
}

export interface LoadBalancerInfo {
  ElbInfoList?: Array<ELBInfo>;
  TargetGroupInfoList?: Array<TargetGroupInfo>;
}

export interface PathParameter {
  PathParameterName: string;
  DatasetParameter: DatasetParameter;
}

export interface AnalysisLoadBalancerTarget {
  Address?: string;
  AvailabilityZone?: string;
  Instance?: AnalysisComponent;
  Port?: number;
}

export interface RevisionLocation {
  GitHubLocation?: GitHubLocation;
  RevisionType?: string;
  S3Location?: AWS_CodeDeploy_DeploymentGroup____S3Location;
}

export interface Sheet {
  SheetId?: string;
  Name?: string;
}

export interface MLUserDataEncryption {
  MLUserDataEncryptionMode: string;
  KmsKeyId?: string;
}

export interface RenameColumnOperation {
  NewColumnName: string;
  ColumnName: string;
}

export interface AWS_EC2_LaunchTemplate____EnclaveOptions {
  Enabled?: boolean;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____ClusterConfig {
  InstanceCount: number;
  InstanceType: string;
  VolumeKmsKeyId?: string;
  VolumeSizeInGB: number;
}

export interface ListenerTls {
  Validation?: ListenerTlsValidationContext;
  Mode: string;
  Certificate: ListenerTlsCertificate;
}

export interface AWS_S3Outposts_Bucket____Rule {
  Status?: string;
  Id?: string;
  AbortIncompleteMultipartUpload?: AWS_S3Outposts_Bucket____AbortIncompleteMultipartUpload;
  ExpirationDate?: string;
  ExpirationInDays?: number;
  Filter?: any;
}

export interface NodeProperties {
  MainNode: number;
  NodeRangeProperties: Array<NodeRangeProperty>;
  NumNodes: number;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____S3ReferenceDataSource {
  BucketARN: string;
  FileKey: string;
  ReferenceRoleARN: string;
}

export interface DynatraceConnectorProfileProperties {
  InstanceUrl: string;
}

export interface IamActionDefinition {
  PolicyArn: string;
  Roles?: Array<string>;
  Groups?: Array<string>;
  Users?: Array<string>;
}

export interface TimestreamAction {
  RoleArn: string;
  DatabaseName: string;
  TableName: string;
  Dimensions: Array<TimestreamDimension>;
  Timestamp?: TimestreamTimestamp;
}

export interface SalesforceConnectorProfileCredentials {
  AccessToken?: string;
  RefreshToken?: string;
  ConnectorOAuthRequest?: ConnectorOAuthRequest;
  ClientCredentialsArn?: string;
}

export interface AWS_S3_Bucket____ReplicationRule {
  DeleteMarkerReplication?: DeleteMarkerReplication;
  Destination: AWS_S3_Bucket____ReplicationDestination;
  Filter?: ReplicationRuleFilter;
  Id?: string;
  Prefix?: string;
  Priority?: number;
  SourceSelectionCriteria?: SourceSelectionCriteria;
  Status: string;
}

export interface VirtualRouterServiceProvider {
  VirtualRouterName: string;
}

export interface CompromisedCredentialsRiskConfigurationType {
  Actions: CompromisedCredentialsActionsType;
  EventFilter?: Array<string>;
}

export interface LaunchTemplateData {
  SecurityGroups?: Array<string>;
  TagSpecifications?: Array<AWS_EC2_LaunchTemplate____TagSpecification>;
  UserData?: string;
  BlockDeviceMappings?: Array<AWS_EC2_LaunchTemplate____BlockDeviceMapping>;
  IamInstanceProfile?: IamInstanceProfile;
  KernelId?: string;
  EbsOptimized?: boolean;
  ElasticGpuSpecifications?: Array<AWS_EC2_LaunchTemplate____ElasticGpuSpecification>;
  ElasticInferenceAccelerators?: Array<LaunchTemplateElasticInferenceAccelerator>;
  Placement?: AWS_EC2_LaunchTemplate____Placement;
  NetworkInterfaces?: Array<AWS_EC2_LaunchTemplate____NetworkInterface>;
  EnclaveOptions?: AWS_EC2_LaunchTemplate____EnclaveOptions;
  ImageId?: string;
  InstanceType?: string;
  Monitoring?: Monitoring;
  HibernationOptions?: AWS_EC2_LaunchTemplate____HibernationOptions;
  MetadataOptions?: AWS_EC2_LaunchTemplate____MetadataOptions;
  LicenseSpecifications?: Array<AWS_EC2_LaunchTemplate____LicenseSpecification>;
  InstanceInitiatedShutdownBehavior?: string;
  CpuOptions?: AWS_EC2_LaunchTemplate____CpuOptions;
  SecurityGroupIds?: Array<string>;
  KeyName?: string;
  DisableApiTermination?: boolean;
  InstanceMarketOptions?: InstanceMarketOptions;
  RamDiskId?: string;
  CapacityReservationSpecification?: CapacityReservationSpecification;
  CreditSpecification?: AWS_EC2_LaunchTemplate____CreditSpecification;
}

export interface AWS_FraudDetector_Detector____EntityType {
  Arn?: string;
  Inline?: boolean;
  Name?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface ParallelismConfiguration {
  ConfigurationType: string;
  ParallelismPerKPU?: number;
  AutoScalingEnabled?: boolean;
  Parallelism?: number;
}

export interface AWS_Greengrass_FunctionDefinitionVersion____DefaultConfig {
  Execution: AWS_Greengrass_FunctionDefinitionVersion____Execution;
}

export interface CsvClassifier {
  QuoteSymbol?: string;
  ContainsHeader?: string;
  Delimiter?: string;
  Header?: Array<string>;
  AllowSingleColumn?: boolean;
  DisableValueTrimming?: boolean;
  Name?: string;
}

export interface AWS_ElasticLoadBalancingV2_Listener____AuthenticateOidcConfig {
  OnUnauthenticatedRequest?: string;
  TokenEndpoint: string;
  SessionTimeout?: string;
  Scope?: string;
  Issuer: string;
  ClientSecret: string;
  UserInfoEndpoint: string;
  ClientId: string;
  AuthorizationEndpoint: string;
  SessionCookieName?: string;
  AuthenticationRequestExtraParams?: Record<string, string>;
}

export interface AWS_ECS_TaskDefinition____ResourceRequirement {
  Type: string;
  Value: string;
}

export interface AccessDescription {
  AccessMethod: AccessMethod;
  AccessLocation: AWS_ACMPCA_CertificateAuthority____GeneralName;
}

export interface AWS_ElasticLoadBalancing_LoadBalancer____HealthCheck {
  HealthyThreshold: string;
  Interval: string;
  Target: string;
  Timeout: string;
  UnhealthyThreshold: string;
}

export interface AWS_EC2_Instance____ElasticGpuSpecification {
  Type: string;
}

export interface AWS_CodeDeploy_DeploymentGroup____TriggerConfig {
  TriggerEvents?: Array<string>;
  TriggerName?: string;
  TriggerTargetArn?: string;
}

export interface RootDirectory {
  Path?: string;
  CreationInfo?: CreationInfo;
}

export interface AnalysisSourceEntity {
  SourceTemplate?: AnalysisSourceTemplate;
}

export interface Resource {
  TableResource?: TableResource;
  DatabaseResource?: DatabaseResource;
  DataLocationResource?: DataLocationResource;
  TableWithColumnsResource?: TableWithColumnsResource;
}

export interface DashboardSourceEntity {
  SourceTemplate?: DashboardSourceTemplate;
}

export interface CustomOriginConfig {
  HTTPPort?: number;
  HTTPSPort?: number;
  OriginKeepaliveTimeout?: number;
  OriginProtocolPolicy: string;
  OriginReadTimeout?: number;
  OriginSSLProtocols?: Array<string>;
}

export interface AWS_QuickSight_Template____ResourcePermission {
  Actions: Array<string>;
  Principal: string;
}

export interface TimestampColumn {
  ColumnName?: string;
  ColumnFormat?: string;
}

export interface MonitoringConfiguration {
  ConfigurationType: string;
  MetricsLevel?: string;
  LogLevel?: string;
}

export interface AWS_WAFv2_WebACL____Statement {
  ByteMatchStatement?: AWS_WAFv2_WebACL____ByteMatchStatement;
  SqliMatchStatement?: AWS_WAFv2_WebACL____SqliMatchStatement;
  XssMatchStatement?: AWS_WAFv2_WebACL____XssMatchStatement;
  SizeConstraintStatement?: AWS_WAFv2_WebACL____SizeConstraintStatement;
  GeoMatchStatement?: AWS_WAFv2_WebACL____GeoMatchStatement;
  RuleGroupReferenceStatement?: RuleGroupReferenceStatement;
  IPSetReferenceStatement?: AWS_WAFv2_WebACL____IPSetReferenceStatement;
  RegexPatternSetReferenceStatement?: AWS_WAFv2_WebACL____RegexPatternSetReferenceStatement;
  ManagedRuleGroupStatement?: ManagedRuleGroupStatement;
  RateBasedStatement?: AWS_WAFv2_WebACL____RateBasedStatement;
  AndStatement?: AWS_WAFv2_WebACL____AndStatement;
  OrStatement?: AWS_WAFv2_WebACL____OrStatement;
  NotStatement?: AWS_WAFv2_WebACL____NotStatement;
  LabelMatchStatement?: AWS_WAFv2_WebACL____LabelMatchStatement;
}

export interface ListenerTlsSdsCertificate {
  SecretName: string;
}

export interface AttributeDefinition {
  AttributeName: string;
  AttributeType: string;
}

export interface CloudFrontOriginAccessIdentityConfig {
  Comment: string;
}

export interface PrefixLevel {
  StorageMetrics: PrefixLevelStorageMetrics;
}

export interface OriginGroups {
  Items?: Array<OriginGroup>;
  Quantity: number;
}

export interface ProductionVariant {
  ModelName: string;
  VariantName: string;
  InitialInstanceCount: number;
  InstanceType: string;
  AcceleratorType?: string;
  InitialVariantWeight: number;
}

export interface StatefulRuleGroupReference {
  ResourceArn: string;
}

export interface RedshiftConnectorProfileProperties {
  DatabaseUrl: string;
  BucketName: string;
  BucketPrefix?: string;
  RoleArn: string;
}

export interface RetryStrategy {
  EvaluateOnExit?: Array<EvaluateOnExit>;
  Attempts?: number;
}

export interface SalesforceSourceProperties {
  Object: string;
  EnableDynamicFieldUpdate?: boolean;
  IncludeDeletedRecords?: boolean;
}

export interface AWS_EMR_InstanceGroupConfig____Configuration {
  Classification?: string;
  ConfigurationProperties?: Record<string, string>;
  Configurations?: Array<AWS_EMR_InstanceGroupConfig____Configuration>;
}

export interface AWS_EC2_ClientVpnEndpoint____TagSpecification {
  ResourceType: string;
  Tags: Array<Tag>;
}

export interface SingularSourceProperties {
  Object: string;
}

export interface EventBridgeDestinationProperties {
  Object: string;
  ErrorHandlingConfig?: ErrorHandlingConfig;
}

export interface InstanceGroupConfig {
  AutoScalingPolicy?: AWS_EMR_Cluster____AutoScalingPolicy;
  BidPrice?: string;
  Configurations?: Array<AWS_EMR_Cluster____Configuration>;
  EbsConfiguration?: AWS_EMR_Cluster____EbsConfiguration;
  InstanceCount: number;
  InstanceType: string;
  Market?: string;
  Name?: string;
}

export interface LoggingProperties {
  BucketName: string;
  S3KeyPrefix?: string;
}

export interface TargetAddress {
  Ip: string;
  Port?: string;
}

export interface AWS_QuickSight_Dashboard____Parameters {
  StringParameters?: Array<AWS_QuickSight_Dashboard____StringParameter>;
  DecimalParameters?: Array<AWS_QuickSight_Dashboard____DecimalParameter>;
  IntegerParameters?: Array<AWS_QuickSight_Dashboard____IntegerParameter>;
  DateTimeParameters?: Array<AWS_QuickSight_Dashboard____DateTimeParameter>;
}

export interface ColumnGroup {
  GeoSpatialColumnGroup?: GeoSpatialColumnGroup;
}

export interface AWS_RoboMaker_SimulationApplication____RobotSoftwareSuite {
  Version: string;
  Name: string;
}

export interface InstanceAssociationOutputLocation {
  S3Location?: S3OutputLocation;
}

export interface MarketoSourceProperties {
  Object: string;
}

export interface DatabaseInputDefinition {
  GlueConnectionName?: string;
  DatabaseTableName?: string;
  TempDirectory?: AWS_DataBrew_Dataset____S3Location;
}

export interface VPCConfig {
  VpcId?: string;
  SubnetIds: Array<string>;
  SecurityGroupIds: Array<string>;
}

export interface OriginGroupMembers {
  Items: Array<OriginGroupMember>;
  Quantity: number;
}

export interface IamInstanceProfileSpecification {
  Arn?: string;
}

export interface ConnectorProfileCredentials {
  Amplitude?: AmplitudeConnectorProfileCredentials;
  Datadog?: DatadogConnectorProfileCredentials;
  Dynatrace?: DynatraceConnectorProfileCredentials;
  GoogleAnalytics?: GoogleAnalyticsConnectorProfileCredentials;
  InforNexus?: InforNexusConnectorProfileCredentials;
  Marketo?: MarketoConnectorProfileCredentials;
  Redshift?: RedshiftConnectorProfileCredentials;
  Salesforce?: SalesforceConnectorProfileCredentials;
  ServiceNow?: ServiceNowConnectorProfileCredentials;
  Singular?: SingularConnectorProfileCredentials;
  Slack?: SlackConnectorProfileCredentials;
  Snowflake?: SnowflakeConnectorProfileCredentials;
  Trendmicro?: TrendmicroConnectorProfileCredentials;
  Veeva?: VeevaConnectorProfileCredentials;
  Zendesk?: ZendeskConnectorProfileCredentials;
}

export interface AWS_AutoScaling_ScalingPolicy____MetricDimension {
  Name: string;
  Value: string;
}

export interface Event {
  Actions?: Array<AWS_IoTEvents_DetectorModel____Action>;
  Condition?: string;
  EventName: string;
}

export interface InstanceNetworkInterfaceSpecification {
  AssociatePublicIpAddress?: boolean;
  DeleteOnTermination?: boolean;
  Description?: string;
  DeviceIndex?: number;
  Groups?: Array<string>;
  Ipv6AddressCount?: number;
  Ipv6Addresses?: Array<AWS_EC2_SpotFleet____InstanceIpv6Address>;
  NetworkInterfaceId?: string;
  PrivateIpAddresses?: Array<AWS_EC2_SpotFleet____PrivateIpAddressSpecification>;
  SecondaryPrivateIpAddressCount?: number;
  SubnetId?: string;
}

export interface DockerVolumeConfiguration {
  Autoprovision?: boolean;
  Driver?: string;
  DriverOpts?: Record<string, string>;
  Labels?: Record<string, string>;
  Scope?: string;
}

export interface ModelQualityJobInput {
  EndpointInput: AWS_SageMaker_ModelQualityJobDefinition____EndpointInput;
  GroundTruthS3Input: AWS_SageMaker_ModelQualityJobDefinition____MonitoringGroundTruthS3Input;
}

export interface ScalingInstruction {
  DisableDynamicScaling?: boolean;
  ServiceNamespace: string;
  PredictiveScalingMaxCapacityBehavior?: string;
  ScalableDimension: string;
  ScalingPolicyUpdateBehavior?: string;
  MinCapacity: number;
  TargetTrackingConfigurations: Array<AWS_AutoScalingPlans_ScalingPlan____TargetTrackingConfiguration>;
  PredictiveScalingMaxCapacityBuffer?: number;
  CustomizedLoadMetricSpecification?: CustomizedLoadMetricSpecification;
  PredefinedLoadMetricSpecification?: PredefinedLoadMetricSpecification;
  ResourceId: string;
  ScheduledActionBufferTime?: number;
  MaxCapacity: number;
  PredictiveScalingMode?: string;
}

export interface CapacityReservationOptionsRequest {
  UsageStrategy?: string;
}

export interface SlackSourceProperties {
  Object: string;
}

export interface Overrides {
  Manifest?: any;
}

export interface AWS_WAF_SqlInjectionMatchSet____FieldToMatch {
  Data?: string;
  Type: string;
}

export interface AWS_WAFv2_RuleGroup____FieldToMatch {
  SingleHeader?: any;
  SingleQueryArgument?: any;
  AllQueryArguments?: any;
  UriPath?: any;
  QueryString?: any;
  Body?: any;
  Method?: any;
  JsonBody?: AWS_WAFv2_RuleGroup____JsonBody;
}

export interface SingularConnectorProfileCredentials {
  ApiKey: string;
}

export interface PrestoParameters {
  Port: number;
  Host: string;
  Catalog: string;
}

export interface StatelessRulesAndCustomActions {
  StatelessRules: Array<StatelessRule>;
  CustomActions?: Array<AWS_NetworkFirewall_RuleGroup____CustomAction>;
}

export interface IotSiteWiseAction {
  RoleArn: string;
  PutAssetPropertyValueEntries: Array<PutAssetPropertyValueEntry>;
}

export interface ExpiryEventsConfiguration {
  DaysBeforeExpiry?: number;
}

export interface AWS_EMR_InstanceGroupConfig____MetricDimension {
  Key: string;
  Value: string;
}

export interface ClientAuthenticationRequest {
  MutualAuthentication?: CertificateAuthenticationRequest;
  Type: string;
  FederatedAuthentication?: FederatedAuthenticationRequest;
  ActiveDirectory?: DirectoryServiceAuthenticationRequest;
}

export interface MethodResponse {
  ResponseModels?: Record<string, string>;
  ResponseParameters?: Record<string, boolean>;
  StatusCode: string;
}

export interface SourceConfiguration {
  ApplicationName: string;
  TemplateName: string;
}

export interface ConnectorDefinitionVersion {
  Connectors: Array<AWS_Greengrass_ConnectorDefinition____Connector>;
}

export interface DashboardSourceTemplate {
  DataSetReferences: Array<AWS_QuickSight_Dashboard____DataSetReference>;
  Arn: string;
}

export interface AWS_ImageBuilder_ImageRecipe____ComponentConfiguration {
  ComponentArn?: string;
}

export interface AWS_KinesisAnalytics_ApplicationOutput____KinesisStreamsOutput {
  ResourceARN: string;
  RoleARN: string;
}

export interface MySqlSettings {
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface AWS_Greengrass_FunctionDefinitionVersion____Function {
  FunctionArn: string;
  FunctionConfiguration: AWS_Greengrass_FunctionDefinitionVersion____FunctionConfiguration;
  Id: string;
}

export interface AWS_EC2_LaunchTemplate____MetadataOptions {
  HttpPutResponseHopLimit?: number;
  HttpTokens?: string;
  HttpEndpoint?: string;
}

export interface NetworkFabricConfiguration {
  Edition: string;
}

export interface AWS_Glue_Partition____Order {
  Column: string;
  SortOrder?: number;
}

export interface DnsConfig {
  DnsRecords: Array<DnsRecord>;
  RoutingPolicy?: string;
  NamespaceId?: string;
}

export interface GeoSpatialColumnGroup {
  Columns: Array<string>;
  CountryCode?: string;
  Name: string;
}

export interface Integration {
  CacheKeyParameters?: Array<string>;
  CacheNamespace?: string;
  ConnectionId?: string;
  ConnectionType?: string;
  ContentHandling?: string;
  Credentials?: string;
  IntegrationHttpMethod?: string;
  IntegrationResponses?: Array<IntegrationResponse>;
  PassthroughBehavior?: string;
  RequestParameters?: Record<string, string>;
  RequestTemplates?: Record<string, string>;
  TimeoutInMillis?: number;
  Type?: string;
  Uri?: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationOutput____DestinationSchema {
  RecordFormatType?: string;
}

export interface SelfManagedEventSource {
  Endpoints?: Endpoints;
}

export interface ConditionResourceType {
  ConditionKey: string;
  ConditionValue: string;
  ConditionType: string;
}

export interface ArchiveRule {
  Filter: Array<AWS_AccessAnalyzer_Analyzer____Filter>;
  RuleName: string;
}

export interface VirtualGatewayListenerTlsCertificate {
  SDS?: VirtualGatewayListenerTlsSdsCertificate;
  ACM?: VirtualGatewayListenerTlsAcmCertificate;
  File?: VirtualGatewayListenerTlsFileCertificate;
}

export interface CloudWatchLogs {
  LogGroup?: string;
  Enabled: boolean;
}

export interface AWS_ImageBuilder_ContainerRecipe____EbsInstanceBlockDeviceSpecification {
  Encrypted?: boolean;
  DeleteOnTermination?: boolean;
  Iops?: number;
  KmsKeyId?: string;
  SnapshotId?: string;
  VolumeSize?: number;
  VolumeType?: string;
}

export interface AWS_AppSync_Resolver____LambdaConflictHandlerConfig {
  LambdaConflictHandlerArn?: string;
}

export interface AnalysisRouteTableRoute {
  destinationCidr?: string;
  destinationPrefixListId?: string;
  egressOnlyInternetGatewayId?: string;
  gatewayId?: string;
  instanceId?: string;
  NatGatewayId?: string;
  NetworkInterfaceId?: string;
  Origin?: string;
  TransitGatewayId?: string;
  VpcPeeringConnectionId?: string;
}

export interface AWS_Budgets_Budget____Subscriber {
  SubscriptionType: string;
  Address: string;
}

export interface SpotFleetLaunchSpecification {
  BlockDeviceMappings?: Array<AWS_EC2_SpotFleet____BlockDeviceMapping>;
  EbsOptimized?: boolean;
  IamInstanceProfile?: IamInstanceProfileSpecification;
  ImageId: string;
  InstanceType: string;
  KernelId?: string;
  KeyName?: string;
  Monitoring?: SpotFleetMonitoring;
  NetworkInterfaces?: Array<InstanceNetworkInterfaceSpecification>;
  Placement?: SpotPlacement;
  RamdiskId?: string;
  SecurityGroups?: Array<GroupIdentifier>;
  SpotPrice?: string;
  SubnetId?: string;
  TagSpecifications?: Array<SpotFleetTagSpecification>;
  UserData?: string;
  WeightedCapacity?: number;
}

export interface GrpcGatewayRouteAction {
  Target: GatewayRouteTarget;
}

export interface AnalysisPacketHeader {
  DestinationAddresses?: Array<string>;
  DestinationPortRanges?: Array<AWS_EC2_NetworkInsightsAnalysis____PortRange>;
  Protocol?: string;
  SourceAddresses?: Array<string>;
  SourcePortRanges?: Array<AWS_EC2_NetworkInsightsAnalysis____PortRange>;
}

export interface AWSAccount {
  Id?: string;
  EmailAddress?: string;
  Name?: string;
}

export interface AWS_SageMaker_Device____Device {
  Description?: string;
  DeviceName: string;
  IotThingName?: string;
}

export interface AWS_MediaConnect_FlowSource____Encryption {
  Algorithm: string;
  ConstantInitializationVector?: string;
  DeviceId?: string;
  KeyType?: string;
  Region?: string;
  ResourceId?: string;
  RoleArn: string;
  SecretArn?: string;
  Url?: string;
}

export interface ServiceNowConnectorProfileCredentials {
  Username: string;
  Password: string;
}

export interface AWS_SageMaker_UserProfile____ResourceSpec {
  InstanceType?: string;
  SageMakerImageArn?: string;
  SageMakerImageVersionArn?: string;
}

export interface ObjectLambdaConfiguration {
  SupportingAccessPoint: string;
  AllowedFeatures?: Array<string>;
  CloudWatchMetricsEnabled?: boolean;
  TransformationConfigurations: Array<TransformationConfiguration>;
}

export interface RoutingStrategy {
  Message?: string;
  FleetId?: string;
  Type: string;
}

export interface PipelineConfig {
  Functions?: Array<string>;
}

export interface ClassicLoadBalancersConfig {
  ClassicLoadBalancers: Array<ClassicLoadBalancer>;
}

export interface NotificationConfig {
  NotificationArn: string;
  NotificationType?: string;
  NotificationEvents?: Array<string>;
}

export interface AWS_EMR_InstanceFleetConfig____Configuration {
  Classification?: string;
  ConfigurationProperties?: Record<string, string>;
  Configurations?: Array<AWS_EMR_InstanceFleetConfig____Configuration>;
}

export interface BlockAction {
  CustomResponse?: CustomResponse;
}

export interface AttributeType {
  Value?: string;
  Name?: string;
}

export interface SchemaConfiguration {
  CatalogId?: string;
  DatabaseName?: string;
  Region?: string;
  RoleARN?: string;
  TableName?: string;
  VersionId?: string;
}

export interface LoginProfile {
  Password: string;
  PasswordResetRequired?: boolean;
}

export interface SourceSelectionCriteria {
  ReplicaModifications?: ReplicaModifications;
  SseKmsEncryptedObjects?: SseKmsEncryptedObjects;
}

export interface AWS_WAFv2_RuleGroup____IPSetReferenceStatement {
  Arn: string;
  IPSetForwardedIPConfig?: AWS_WAFv2_RuleGroup____IPSetForwardedIPConfiguration;
}

export interface AWS_OpsWorks_Stack____Source {
  Password?: string;
  Revision?: string;
  SshKey?: string;
  Type?: string;
  Url?: string;
  Username?: string;
}

export interface AWS_QuickSight_DataSource____ResourcePermission {
  Actions: Array<string>;
  Principal: string;
}

export interface ConnectionSettings {
  IdleTimeout: number;
}

export interface StorageClassAnalysis {
  DataExport?: AWS_S3_Bucket____DataExport;
}

export interface FederatedAuthenticationRequest {
  SelfServiceSAMLProviderArn?: string;
  SAMLProviderArn: string;
}

export interface HttpParameters {
  HeaderParameters?: Record<string, string>;
  PathParameterValues?: Array<string>;
  QueryStringParameters?: Record<string, string>;
}

export interface AlertTarget {
  AlertTargetArn: string;
  RoleArn: string;
}

export interface AWS_Greengrass_LoggerDefinition____Logger {
  Space?: number;
  Type: string;
  Level: string;
  Id: string;
  Component: string;
}

export interface KerberosAttributes {
  ADDomainJoinPassword?: string;
  ADDomainJoinUser?: string;
  CrossRealmTrustPrincipalPassword?: string;
  KdcAdminPassword: string;
  Realm: string;
}

export interface NeptuneSettings {
  MaxRetryCount?: number;
  MaxFileSize?: number;
  S3BucketFolder?: string;
  ErrorRetryDuration?: number;
  IamAuthEnabled?: boolean;
  S3BucketName?: string;
  ServiceAccessRoleArn?: string;
}

export interface BackendDefaults {
  ClientPolicy?: ClientPolicy;
}

export interface AwsOrganizationsSource {
  OrganizationalUnits?: Array<string>;
  OrganizationSourceType: string;
}

export interface ParametersInCacheKeyAndForwardedToOrigin {
  CookiesConfig: AWS_CloudFront_CachePolicy____CookiesConfig;
  EnableAcceptEncodingBrotli?: boolean;
  EnableAcceptEncodingGzip: boolean;
  HeadersConfig: AWS_CloudFront_CachePolicy____HeadersConfig;
  QueryStringsConfig: AWS_CloudFront_CachePolicy____QueryStringsConfig;
}

export interface AWS_ECS_TaskDefinition____AuthorizationConfig {
  IAM?: string;
  AccessPointId?: string;
}

export interface SplunkRetryOptions {
  DurationInSeconds?: number;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____ConstraintsResource {
  S3Uri?: string;
}

export interface Content {
  S3ObjectVersion?: string;
  S3Bucket: string;
  S3Key: string;
}

export interface QueryAction {
  Filters?: Array<AWS_IoTAnalytics_Dataset____Filter>;
  SqlQuery: string;
}

export interface AWS_SSM_Association____Target {
  Key: string;
  Values: Array<string>;
}

export interface UpdateDeviceCertificateParams {
  Action: string;
}

export interface AWS_S3_AccessPoint____VpcConfiguration {
  VpcId?: string;
}

export interface TlsConfig {
  ServerNameToVerify?: string;
}

export interface StageTransition {
  Reason: string;
  StageName: string;
}

export interface VirtualGatewayGrpcConnectionPool {
  MaxRequests: number;
}

export interface SyncSource {
  IncludeFutureRegions?: boolean;
  SourceRegions: Array<string>;
  SourceType: string;
  AwsOrganizationsSource?: AwsOrganizationsSource;
}

export interface MaintenanceWindowAutomationParameters {
  Parameters?: any;
  DocumentVersion?: string;
}

export interface HttpEndpointRequestConfiguration {
  ContentEncoding?: string;
  CommonAttributes?: Array<HttpEndpointCommonAttribute>;
}

export interface AWS_IoTAnalytics_Channel____CustomerManagedS3 {
  Bucket: string;
  RoleArn: string;
  KeyPrefix?: string;
}

export interface OpenIDConnectConfig {
  Issuer?: string;
  ClientId?: string;
  AuthTTL?: number;
  IatTTL?: number;
}

export interface Recipe {
  Name: string;
  Version?: string;
}

export interface CreateRule {
  IntervalUnit?: string;
  Times?: Array<string>;
  CronExpression?: string;
  Interval?: number;
  Location?: string;
}

export interface AWS_EMR_InstanceGroupConfig____SimpleScalingPolicyConfiguration {
  AdjustmentType?: string;
  CoolDown?: number;
  ScalingAdjustment: number;
}

export interface AWS_KinesisAnalyticsV2_ApplicationOutput____Output {
  DestinationSchema: AWS_KinesisAnalyticsV2_ApplicationOutput____DestinationSchema;
  LambdaOutput?: AWS_KinesisAnalyticsV2_ApplicationOutput____LambdaOutput;
  KinesisFirehoseOutput?: AWS_KinesisAnalyticsV2_ApplicationOutput____KinesisFirehoseOutput;
  KinesisStreamsOutput?: AWS_KinesisAnalyticsV2_ApplicationOutput____KinesisStreamsOutput;
  Name?: string;
}

export interface AWS_Greengrass_FunctionDefinition____DefaultConfig {
  Execution: AWS_Greengrass_FunctionDefinition____Execution;
}

export interface CapacityReservationSpecification {
  CapacityReservationPreference?: string;
  CapacityReservationTarget?: CapacityReservationTarget;
}

export interface EndPoint {
  KinesisStreamConfig: KinesisStreamConfig;
  StreamType: string;
}

export interface ChefConfiguration {
  BerkshelfVersion?: string;
  ManageBerkshelf?: boolean;
}

export interface VirtualGatewayConnectionPool {
  HTTP2?: VirtualGatewayHttp2ConnectionPool;
  HTTP?: VirtualGatewayHttpConnectionPool;
  GRPC?: VirtualGatewayGrpcConnectionPool;
}

export interface RelationalTable {
  DataSourceArn: string;
  InputColumns: Array<InputColumn>;
  Schema?: string;
  Catalog?: string;
  Name: string;
}

export interface VirtualNodeTcpConnectionPool {
  MaxConnections: number;
}

export interface AWS_KinesisAnalytics_Application____KinesisStreamsInput {
  ResourceARN: string;
  RoleARN: string;
}

export interface AWS_RoboMaker_SimulationApplication____SourceConfig {
  S3Bucket: string;
  Architecture: string;
  S3Key: string;
}

export interface InputColumn {
  Type: string;
  Name: string;
}

export interface RegistryCredential {
  Credential: string;
  CredentialProvider: string;
}

export interface AWS_EFS_FileSystem____LifecyclePolicy {
  TransitionToIA: string;
}

export interface Attribute {
  JsonPath: string;
}

export interface Sns {
  Payload?: Payload;
  TargetArn: string;
}

export interface AWS_AppMesh_VirtualGateway____SubjectAlternativeNames {
  Match: AWS_AppMesh_VirtualGateway____SubjectAlternativeNameMatchers;
}

export interface GrpcRouteMetadata {
  Invert?: boolean;
  Name: string;
  Match?: GrpcRouteMetadataMatchMethod;
}

export interface AWS_MSK_Cluster____EncryptionAtRest {
  DataVolumeKMSKeyId: string;
}

export interface OnExit {
  Events?: Array<Event>;
}

export interface S3ReportExportConfig {
  Path?: string;
  Bucket: string;
  Packaging?: string;
  EncryptionKey?: string;
  BucketOwner?: string;
  EncryptionDisabled?: boolean;
}

export interface User {
  Username: string;
  Groups?: Array<string>;
  ConsoleAccess?: boolean;
  Password: string;
}

export interface AWS_DataBrew_Job____Output {
  CompressionFormat?: string;
  Format?: string;
  FormatOptions?: OutputFormatOptions;
  PartitionColumns?: Array<string>;
  Location: AWS_DataBrew_Job____S3Location;
  Overwrite?: boolean;
}

export interface OnSuccess {
  Destination: string;
}

export interface AWS_WAF_ByteMatchSet____ByteMatchTuple {
  FieldToMatch: AWS_WAF_ByteMatchSet____FieldToMatch;
  PositionalConstraint: string;
  TargetString?: string;
  TargetStringBase64?: string;
  TextTransformation: string;
}

export interface DatasetContentDeliveryRuleDestination {
  IotEventsDestinationConfiguration?: IotEventsDestinationConfiguration;
  S3DestinationConfiguration?: AWS_IoTAnalytics_Dataset____S3DestinationConfiguration;
}

export interface AWS_AutoScaling_ScalingPolicy____TargetTrackingConfiguration {
  CustomizedMetricSpecification?: AWS_AutoScaling_ScalingPolicy____CustomizedMetricSpecification;
  DisableScaleIn?: boolean;
  PredefinedMetricSpecification?: AWS_AutoScaling_ScalingPolicy____PredefinedMetricSpecification;
  TargetValue: number;
}

export interface MountPoint {
  ContainerPath?: string;
  ReadOnly?: boolean;
  SourceVolume?: string;
}

export interface Application {
  AdditionalInfo?: Record<string, string>;
  Args?: Array<string>;
  Name?: string;
  Version?: string;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____MonitoringResources {
  ClusterConfig: AWS_SageMaker_ModelQualityJobDefinition____ClusterConfig;
}

export interface HttpRouteMatch {
  Scheme?: string;
  Headers?: Array<HttpRouteHeader>;
  Prefix: string;
  Method?: string;
}

export interface AWS_Glue_SecurityConfiguration____EncryptionConfiguration {
  S3Encryptions?: S3Encryptions;
  CloudWatchEncryption?: CloudWatchEncryption;
  JobBookmarksEncryption?: JobBookmarksEncryption;
}

export interface RemoveAttributes {
  Next?: string;
  Attributes?: Array<string>;
  Name?: string;
}

export interface PathOptions {
  FilesLimit?: FilesLimit;
  LastModifiedDateCondition?: FilterExpression;
  Parameters?: Array<PathParameter>;
}

export interface TaskInvocationParameters {
  MaintenanceWindowRunCommandParameters?: MaintenanceWindowRunCommandParameters;
  MaintenanceWindowAutomationParameters?: MaintenanceWindowAutomationParameters;
  MaintenanceWindowStepFunctionsParameters?: MaintenanceWindowStepFunctionsParameters;
  MaintenanceWindowLambdaParameters?: MaintenanceWindowLambdaParameters;
}

export interface JsonFormatDescriptor {
  FileCompression?: string;
  Charset?: string;
}

export interface RuleGroupReferenceStatement {
  Arn: string;
  ExcludedRules?: Array<ExcludedRule>;
}

export interface AWS_AppSync_DataSource____LambdaConfig {
  LambdaFunctionArn: string;
}

export interface GatewayRouteTarget {
  VirtualService: GatewayRouteVirtualService;
}

export interface EC2TagSet {
  Ec2TagSetList?: Array<EC2TagSetListObject>;
}

export interface AWS_AppMesh_VirtualNode____HttpTimeout {
  PerRequest?: AWS_AppMesh_VirtualNode____Duration;
  Idle?: AWS_AppMesh_VirtualNode____Duration;
}

export interface AWS_AutoScalingPlans_ScalingPlan____MetricDimension {
  Value: string;
  Name: string;
}

export interface GlobalSecondaryIndex {
  ContributorInsightsSpecification?: ContributorInsightsSpecification;
  IndexName: string;
  KeySchema: Array<KeySchema>;
  Projection: Projection;
  ProvisionedThroughput?: AWS_DynamoDB_Table____ProvisionedThroughput;
}

export interface BrokerLogs {
  S3?: AWS_MSK_Cluster____S3;
  Firehose?: AWS_MSK_Cluster____Firehose;
  CloudWatchLogs?: CloudWatchLogs;
}

export interface ResourceCollectionFilter {
  CloudFormation?: CloudFormationCollectionFilter;
}

export interface AWS_NetworkFirewall_FirewallPolicy____PublishMetricAction {
  Dimensions: Array<AWS_NetworkFirewall_FirewallPolicy____Dimension>;
}

export interface DatasetParameter {
  Name: string;
  Type: string;
  DatetimeOptions?: DatetimeOptions;
  CreateColumn?: boolean;
  Filter?: FilterExpression;
}

export interface RedshiftDestinationProperties {
  Object: string;
  IntermediateBucketName: string;
  BucketPrefix?: string;
  ErrorHandlingConfig?: ErrorHandlingConfig;
}

export interface PolicyQualifierInfo {
  PolicyQualifierId: string;
  Qualifier: Qualifier;
}

export interface RedirectRule {
  HostName?: string;
  HttpRedirectCode?: string;
  Protocol?: string;
  ReplaceKeyPrefixWith?: string;
  ReplaceKeyWith?: string;
}

export interface AWS_Events_EventBusPolicy____Condition {
  Type?: string;
  Value?: string;
  Key?: string;
}

export interface AWS_EMR_InstanceGroupConfig____ScalingRule {
  Action: AWS_EMR_InstanceGroupConfig____ScalingAction;
  Description?: string;
  Name: string;
  Trigger: AWS_EMR_InstanceGroupConfig____ScalingTrigger;
}

export interface AWS_Batch_JobDefinition____Secret {
  ValueFrom: string;
  Name: string;
}

export interface RuleOption {
  Keyword: string;
  Settings?: Array<string>;
}

export interface RuleCondition {
  Field?: string;
  Values?: Array<string>;
  HttpRequestMethodConfig?: HttpRequestMethodConfig;
  PathPatternConfig?: PathPatternConfig;
  HttpHeaderConfig?: HttpHeaderConfig;
  SourceIpConfig?: SourceIpConfig;
  HostHeaderConfig?: HostHeaderConfig;
  QueryStringConfig?: QueryStringConfig;
}

export interface OutputLocation {
  Bucket: string;
  Key?: string;
}

export interface AWS_AppMesh_VirtualNode____HealthCheck {
  Path?: string;
  UnhealthyThreshold: number;
  Port?: number;
  HealthyThreshold: number;
  TimeoutMillis: number;
  Protocol: string;
  IntervalMillis: number;
}

export interface AlarmConfiguration {
  Alarms?: Array<AWS_CodeDeploy_DeploymentGroup____Alarm>;
  Enabled?: boolean;
  IgnorePollAlarmFailure?: boolean;
}

export interface AWS_SageMaker_MonitoringSchedule____MonitoringOutputConfig {
  KmsKeyId?: string;
  MonitoringOutputs: Array<AWS_SageMaker_MonitoringSchedule____MonitoringOutput>;
}

export interface ObjectLockRule {
  DefaultRetention?: DefaultRetention;
}

export interface Taint {
  Value?: string;
  Effect?: string;
  Key?: string;
}

export interface AWS_IoTAnalytics_Dataset____VersioningConfiguration {
  MaxVersions?: number;
  Unlimited?: boolean;
}

export interface Datastore {
  DatastoreName?: string;
  Name?: string;
}

export interface VirtualGatewayClientTlsCertificate {
  SDS?: VirtualGatewayListenerTlsSdsCertificate;
  File?: VirtualGatewayListenerTlsFileCertificate;
}

export interface SslConfiguration {
  Certificate?: string;
  Chain?: string;
  PrivateKey?: string;
}

export interface Qualifier {
  CpsUri: string;
}

export interface AWS_QuickSight_Analysis____DataSetReference {
  DataSetArn: string;
  DataSetPlaceholder: string;
}

export interface GrpcGatewayRouteMatch {
  ServiceName?: string;
}

export interface PatchFilter {
  Values?: Array<string>;
  Key?: string;
}

export interface FilesLimit {
  MaxFiles: number;
  OrderedBy?: string;
  Order?: string;
}

export interface BorrowConfiguration {
  MaxTimeToLiveInMinutes: number;
  AllowEarlyCheckIn: boolean;
}

export interface KinesisConfiguration {
  StreamArn?: string;
  AggregationEnabled?: boolean;
}

export interface Tier {
  Name?: string;
  Type?: string;
  Version?: string;
}

export interface ContributorInsightsSpecification {
  Enabled: boolean;
}

export interface Sqs {
  Payload?: Payload;
  QueueUrl: string;
  UseBase64?: boolean;
}

export interface AWS_ApiGateway_DomainName____MutualTlsAuthentication {
  TruststoreUri?: string;
  TruststoreVersion?: string;
}

export interface LookoutMetricsDestinationProperties {
  Object?: string;
}

export interface SnowflakeConnectorProfileCredentials {
  Username: string;
  Password: string;
}

export interface ConnectionDrainingPolicy {
  Enabled: boolean;
  Timeout?: number;
}

export interface SparkParameters {
  Port: number;
  Host: string;
}

export interface VirtualGatewayListenerTlsValidationContext {
  SubjectAlternativeNames?: AWS_AppMesh_VirtualGateway____SubjectAlternativeNames;
  Trust: VirtualGatewayListenerTlsValidationContextTrust;
}

export interface AWS_EC2_Instance____CpuOptions {
  CoreCount?: number;
  ThreadsPerCore?: number;
}

export interface GeoRestriction {
  Locations?: Array<string>;
  RestrictionType: string;
}

export interface CsvOptions {
  Delimiter?: string;
  HeaderRow?: boolean;
}

export interface AWS_WAFv2_WebACL____LabelMatchStatement {
  Scope: string;
  Key: string;
}

export interface AwsCloudMapServiceDiscovery {
  NamespaceName: string;
  ServiceName: string;
  Attributes?: Array<AwsCloudMapInstanceAttribute>;
}

export interface AuroraParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface FleetLaunchTemplateConfigRequest {
  LaunchTemplateSpecification?: FleetLaunchTemplateSpecificationRequest;
  Overrides?: Array<FleetLaunchTemplateOverridesRequest>;
}

export interface FormatOptions {
  Json?: JsonOptions;
  Excel?: ExcelOptions;
  Csv?: CsvOptions;
}

export interface AWS_SageMaker_Workteam____NotificationConfiguration {
  NotificationTopicArn: string;
}

export interface AWS_WAFv2_WebACL____JsonMatchPattern {
  All?: any;
  IncludedPaths?: Array<string>;
}

export interface HopDestination {
  WaitMinutes?: number;
  Priority?: number;
  Queue?: string;
}

export interface AWS_WAFv2_WebACL____AndStatement {
  Statements: Array<AWS_WAFv2_WebACL____Statement>;
}

export interface LogDestination {
  CloudWatchLogsLogGroup?: CloudWatchLogsLogGroup;
}

export interface AWS_WAFRegional_ByteMatchSet____FieldToMatch {
  Type: string;
  Data?: string;
}

export interface RowLevelPermissionDataSet {
  Arn: string;
  Namespace?: string;
  PermissionPolicy: string;
}

export interface DemodulationConfig {
  UnvalidatedJSON?: string;
}

export interface AWS_EC2_Instance____LaunchTemplateSpecification {
  LaunchTemplateId?: string;
  LaunchTemplateName?: string;
  Version: string;
}

export interface MetricsCollection {
  Granularity: string;
  Metrics?: Array<string>;
}

export interface CloudWatchLogsConfig {
  Status: string;
  GroupName?: string;
  StreamName?: string;
}

export interface KeySchema {
  AttributeName: string;
  KeyType: string;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____LocalVolumeResourceData {
  SourcePath: string;
  DestinationPath: string;
  GroupOwnerSetting?: AWS_Greengrass_ResourceDefinitionVersion____GroupOwnerSetting;
}

export interface ResultConfiguration {
  EncryptionConfiguration?: AWS_Athena_WorkGroup____EncryptionConfiguration;
  OutputLocation?: string;
}

export interface VirtualNodeHttpConnectionPool {
  MaxConnections: number;
  MaxPendingRequests?: number;
}

export interface DetectorModelDefinition {
  InitialStateName: string;
  States: Array<State>;
}

export interface SourceFlowConfig {
  ConnectorType: string;
  ConnectorProfileName?: string;
  SourceConnectorProperties: SourceConnectorProperties;
  IncrementalPullConfig?: IncrementalPullConfig;
}

export interface AWS_DataSync_LocationNFS____MountOptions {
  Version?: string;
}

export interface AWS_SSM_PatchBaseline____Rule {
  ApproveUntilDate?: PatchStringDate;
  EnableNonSecurity?: boolean;
  PatchFilterGroup?: PatchFilterGroup;
  ApproveAfterDays?: number;
  ComplianceLevel?: string;
}

export interface AWS_ElastiCache_CacheCluster____KinesisFirehoseDestinationDetails {
  DeliveryStream?: string;
}

export interface ViewerCertificate {
  AcmCertificateArn?: string;
  CloudFrontDefaultCertificate?: boolean;
  IamCertificateId?: string;
  MinimumProtocolVersion?: string;
  SslSupportMethod?: string;
}

export interface AWS_WAFv2_RuleGroup____RateBasedStatement {
  Limit: number;
  AggregateKeyType: string;
  ScopeDownStatement?: AWS_WAFv2_RuleGroup____Statement;
  ForwardedIPConfig?: AWS_WAFv2_RuleGroup____ForwardedIPConfiguration;
}

export interface VirtualNodeServiceProvider {
  VirtualNodeName: string;
}

export interface AWS_EMR_Cluster____Configuration {
  Classification?: string;
  ConfigurationProperties?: Record<string, string>;
  Configurations?: Array<AWS_EMR_Cluster____Configuration>;
}

export interface AWS_EMR_InstanceFleetConfig____InstanceTypeConfig {
  BidPrice?: string;
  BidPriceAsPercentageOfOnDemandPrice?: number;
  Configurations?: Array<AWS_EMR_InstanceFleetConfig____Configuration>;
  EbsConfiguration?: AWS_EMR_InstanceFleetConfig____EbsConfiguration;
  InstanceType: string;
  WeightedCapacity?: number;
}

export interface AWS_WAFRegional_XssMatchSet____XssMatchTuple {
  TextTransformation: string;
  FieldToMatch: AWS_WAFRegional_XssMatchSet____FieldToMatch;
}

export interface CountAction {
  CustomRequestHandling?: CustomRequestHandling;
}

export interface AWS_S3_Bucket____Rule {
  AbortIncompleteMultipartUpload?: AWS_S3_Bucket____AbortIncompleteMultipartUpload;
  ExpirationDate?: string;
  ExpirationInDays?: number;
  Id?: string;
  NoncurrentVersionExpirationInDays?: number;
  NoncurrentVersionTransition?: NoncurrentVersionTransition;
  NoncurrentVersionTransitions?: Array<NoncurrentVersionTransition>;
  Prefix?: string;
  Status: string;
  TagFilters?: Array<AWS_S3_Bucket____TagFilter>;
  Transition?: Transition;
  Transitions?: Array<Transition>;
}

export interface RetainRule {
  IntervalUnit?: string;
  Count?: number;
  Interval?: number;
}

export interface KernelCapabilities {
  Add?: Array<string>;
  Drop?: Array<string>;
}

export interface ReplicaRegion {
  KmsKeyId?: string;
  Region: string;
}

export interface AWS_GameLift_GameServerGroup____LaunchTemplate {
  LaunchTemplateId?: string;
  LaunchTemplateName?: string;
  Version?: string;
}

export interface AWS_KinesisAnalytics_Application____RecordColumn {
  Mapping?: string;
  SqlType: string;
  Name: string;
}

export interface PatchFilterGroup {
  PatchFilters?: Array<PatchFilter>;
}

export interface AWS_Cognito_UserPool____LambdaConfig {
  CreateAuthChallenge?: string;
  PreSignUp?: string;
  KMSKeyID?: string;
  UserMigration?: string;
  PostAuthentication?: string;
  VerifyAuthChallengeResponse?: string;
  PreAuthentication?: string;
  DefineAuthChallenge?: string;
  PreTokenGeneration?: string;
  CustomSMSSender?: CustomSMSSender;
  PostConfirmation?: string;
  CustomMessage?: string;
  CustomEmailSender?: CustomEmailSender;
}

export interface PolicyDetails {
  ResourceTypes?: Array<string>;
  Schedules?: Array<AWS_DLM_LifecyclePolicy____Schedule>;
  PolicyType?: string;
  EventSource?: EventSource;
  Parameters?: AWS_DLM_LifecyclePolicy____Parameters;
  Actions?: Array<AWS_DLM_LifecyclePolicy____Action>;
  TargetTags?: Array<Tag>;
  ResourceLocations?: Array<string>;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____StoppingCondition {
  MaxRuntimeInSeconds: number;
}

export interface MariaDbParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface TableInput {
  Owner?: string;
  ViewOriginalText?: string;
  Description?: string;
  TableType?: string;
  Parameters?: any;
  ViewExpandedText?: string;
  StorageDescriptor?: AWS_Glue_Table____StorageDescriptor;
  TargetTable?: TableIdentifier;
  PartitionKeys?: Array<AWS_Glue_Table____Column>;
  Retention?: number;
  Name?: string;
}

export interface ProjectCache {
  Modes?: Array<string>;
  Type: string;
  Location?: string;
}

export interface VirtualGatewayListenerTlsFileCertificate {
  PrivateKey: string;
  CertificateChain: string;
}

export interface RemediationParameterValue {
  ResourceValue?: ResourceValue;
  StaticValue?: StaticValue;
}

export interface AWS_Macie_FindingsFilter____FindingCriteria {
  Criterion?: Criterion;
}

export interface CertificateConfiguration {
  CertificateType: string;
}

export interface ScriptBootstrapActionConfig {
  Args?: Array<string>;
  Path: string;
}

export interface TracingConfig {
  Mode?: string;
}

export interface IotTopicPublish {
  MqttTopic: string;
  Payload?: Payload;
}

export interface AdvancedSecurityOptionsInput {
  Enabled?: boolean;
  InternalUserDatabaseEnabled?: boolean;
  MasterUserOptions?: MasterUserOptions;
}

export interface AutoScalingGroupProvider {
  AutoScalingGroupArn: string;
  ManagedScaling?: ManagedScaling;
  ManagedTerminationProtection?: string;
}

export interface ProjectBuildBatchConfig {
  CombineArtifacts?: boolean;
  ServiceRole?: string;
  TimeoutInMins?: number;
  Restrictions?: BatchRestrictions;
}

export interface MetricsConfiguration {
  Id: string;
  Prefix?: string;
  TagFilters?: Array<AWS_S3_Bucket____TagFilter>;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____EndpointInput {
  EndpointName: string;
  LocalPath: string;
  S3DataDistributionType?: string;
  S3InputMode?: string;
  StartTimeOffset?: string;
  EndTimeOffset?: string;
  InferenceAttribute?: string;
  ProbabilityAttribute?: string;
  ProbabilityThresholdAttribute?: number;
}

export interface AWS_IoTAnalytics_Datastore____CustomerManagedS3 {
  Bucket: string;
  RoleArn: string;
  KeyPrefix?: string;
}

export interface UpsolverS3OutputFormatConfig {
  FileType?: string;
  PrefixConfig: PrefixConfig;
  AggregationConfig?: AggregationConfig;
}

export interface AWS_Glue_Partition____SchemaReference {
  SchemaId?: AWS_Glue_Partition____SchemaId;
  SchemaVersionNumber?: number;
  SchameVersionId?: string;
}

export interface GrpcGatewayRoute {
  Action: GrpcGatewayRouteAction;
  Match: GrpcGatewayRouteMatch;
}

export interface Metadata {
  Name: string;
  Value: string;
}

export interface AWS_IoTAnalytics_Dataset____Schedule {
  ScheduleExpression: string;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____RecordColumn {
  Mapping?: string;
  SqlType: string;
  Name: string;
}

export interface ProvisioningHook {
  TargetArn?: string;
  PayloadVersion?: string;
}

export interface GrokClassifier {
  CustomPatterns?: string;
  GrokPattern: string;
  Classification: string;
  Name?: string;
}

export interface HttpConfig {
  Endpoint: string;
  AuthorizationConfig?: AWS_AppSync_DataSource____AuthorizationConfig;
}

export interface DeviceRegistryEnrich {
  Attribute?: string;
  Next?: string;
  ThingName?: string;
  RoleArn?: string;
  Name?: string;
}

export interface AWS_Config_ConformancePack____ConformancePackInputParameter {
  ParameterName: string;
  ParameterValue: string;
}

export type FilterGroup = WebhookFilter[];

export interface Registry {
  Name?: string;
  Arn?: string;
}

export interface PredefinedScalingMetricSpecification {
  ResourceLabel?: string;
  PredefinedScalingMetricType: string;
}

export type AWS_SageMaker_ModelExplainabilityJobDefinition____Environment = undefined;

export interface BackupPlanResourceType {
  BackupPlanName: string;
  AdvancedBackupSettings?: Array<AdvancedBackupSettingResourceType>;
  BackupPlanRule: Array<BackupRuleResourceType>;
}

export interface EncryptionConfig {
  Resources?: Array<string>;
  Provider?: Provider;
}

export interface DataResource {
  Type: string;
  Values?: Array<string>;
}

export interface VirtualGatewayLogging {
  AccessLog?: VirtualGatewayAccessLog;
}

export interface DynamoDBv2Action {
  PutItem?: PutItemInput;
  RoleArn?: string;
}

export interface AntennaDownlinkDemodDecodeConfig {
  SpectrumConfig?: SpectrumConfig;
  DemodulationConfig?: DemodulationConfig;
  DecodeConfig?: DecodeConfig;
}

export interface AWS_QuickSight_Dashboard____DataSetReference {
  DataSetArn: string;
  DataSetPlaceholder: string;
}

export interface TileStyle {
  Border?: BorderStyle;
}

export interface NotificationObjectType {
  BackupVaultEvents: Array<string>;
  SNSTopicArn: string;
}

export interface SqlApplicationConfiguration {
  Inputs?: Array<AWS_KinesisAnalyticsV2_Application____Input>;
}

export interface CognitoUserPoolConfig {
  AppIdClientRegex?: string;
  UserPoolId?: string;
  AwsRegion?: string;
}

export interface JobBookmarksEncryption {
  KmsKeyArn?: string;
  JobBookmarksEncryptionMode?: string;
}

export interface AWS_IoTAnalytics_Channel____RetentionPeriod {
  NumberOfDays?: number;
  Unlimited?: boolean;
}

export interface AWS_Glue_Table____SerdeInfo {
  Parameters?: any;
  SerializationLibrary?: string;
  Name?: string;
}

export interface BatchRestrictions {
  ComputeTypesAllowed?: Array<string>;
  MaximumBuildsAllowed?: number;
}

export type AdditionalAuthenticationProviders = AdditionalAuthenticationProvider[];

export interface AWS_GameLift_Script____S3Location {
  ObjectVersion?: string;
  Bucket: string;
  Key: string;
  RoleArn: string;
}

export interface AWS_KinesisAnalyticsV2_Application____InputProcessingConfiguration {
  InputLambdaProcessor?: AWS_KinesisAnalyticsV2_Application____InputLambdaProcessor;
}

export interface EncryptionInTransit {
  ClientBroker?: string;
  InCluster?: boolean;
}

export interface Monitors {
  AlarmArn?: string;
  AlarmRoleArn?: string;
}

export interface PatchSource {
  Products?: Array<string>;
  Configuration?: string;
  Name?: string;
}

export interface CapacityReservationTarget {
  CapacityReservationResourceGroupArn?: string;
  CapacityReservationId?: string;
}

export interface AWS_KinesisAnalytics_Application____KinesisFirehoseInput {
  ResourceARN: string;
  RoleARN: string;
}

export interface ListenerTlsFileCertificate {
  PrivateKey: string;
  CertificateChain: string;
}

export interface AWS_Config_ConfigRule____Source {
  Owner: string;
  SourceDetails?: Array<SourceDetail>;
  SourceIdentifier: string;
}

export interface SecurityDetails {
  SubnetIds?: Array<string>;
  SecurityGroupIds?: Array<string>;
  RoleArn?: string;
}

export interface AWS_ApiGateway_RestApi____S3Location {
  Bucket?: string;
  ETag?: string;
  Key?: string;
  Version?: string;
}

export interface AWS_SageMaker_MonitoringSchedule____StatisticsResource {
  S3Uri?: string;
}

export interface AWS_Batch_JobDefinition____NetworkConfiguration {
  AssignPublicIp?: string;
}

export interface AWS_ElasticLoadBalancingV2_Listener____Certificate {
  CertificateArn?: string;
}

export interface AWS_QuickSight_Dashboard____StringParameter {
  Values: Array<string>;
  Name: string;
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule____RedirectConfig {
  Path?: string;
  Query?: string;
  Port?: string;
  Host?: string;
  Protocol?: string;
  StatusCode: string;
}

export interface ApplicationCodeConfiguration {
  CodeContentType: string;
  CodeContent: CodeContent;
}

export interface AWS_IoTAnalytics_Dataset____RetentionPeriod {
  NumberOfDays: number;
  Unlimited: boolean;
}

export interface AccountAggregationSource {
  AllAwsRegions?: boolean;
  AwsRegions?: Array<string>;
  AccountIds: Array<string>;
}

export interface AWS_ACMPCA_Certificate____GeneralName {
  OtherName?: AWS_ACMPCA_Certificate____OtherName;
  Rfc822Name?: string;
  DnsName?: string;
  DirectoryName?: AWS_ACMPCA_Certificate____Subject;
  EdiPartyName?: AWS_ACMPCA_Certificate____EdiPartyName;
  UniformResourceIdentifier?: string;
  IpAddress?: string;
  RegisteredId?: string;
}

export interface AWS_GameLift_GameServerGroup____AutoScalingPolicy {
  EstimatedInstanceWarmup?: number;
  TargetTrackingConfiguration: AWS_GameLift_GameServerGroup____TargetTrackingConfiguration;
}

export interface ZoneAwarenessConfig {
  AvailabilityZoneCount?: number;
}

export interface AWS_SageMaker_MonitoringSchedule____VpcConfig {
  SecurityGroupIds: Array<string>;
  Subnets: Array<string>;
}

export interface MinimumHealthyHosts {
  Type: string;
  Value: number;
}

export interface TlsValidationContext {
  SubjectAlternativeNames?: AWS_AppMesh_VirtualNode____SubjectAlternativeNames;
  Trust: TlsValidationContextTrust;
}

export interface AWS_Route53_RecordSetGroup____GeoLocation {
  ContinentCode?: string;
  CountryCode?: string;
  SubdivisionCode?: string;
}

export interface VirtualRouterSpec {
  Listeners: Array<VirtualRouterListener>;
}

export interface AWS_ApiGateway_RestApi____EndpointConfiguration {
  Types?: Array<string>;
  VpcEndpointIds?: Array<string>;
}

export interface VirtualGatewayListenerTls {
  Validation?: VirtualGatewayListenerTlsValidationContext;
  Mode: string;
  Certificate: VirtualGatewayListenerTlsCertificate;
}

export interface AWS_Batch_JobDefinition____LogConfiguration {
  SecretOptions?: Array<AWS_Batch_JobDefinition____Secret>;
  Options?: any;
  LogDriver: string;
}

export interface Recipes {
  Configure?: Array<string>;
  Deploy?: Array<string>;
  Setup?: Array<string>;
  Shutdown?: Array<string>;
  Undeploy?: Array<string>;
}

export interface AWS_QuickSight_Analysis____DateTimeParameter {
  Values: Array<string>;
  Name: string;
}

export interface PolicyTag {
  Key: string;
  Value: string;
}

export interface HttpEndpointConfiguration {
  Url: string;
  AccessKey?: string;
  Name?: string;
}

export interface AWS_DLM_LifecyclePolicy____Parameters {
  ExcludeBootVolume?: boolean;
  NoReboot?: boolean;
}

export interface AWS_Budgets_BudgetsAction____Definition {
  IamActionDefinition?: IamActionDefinition;
  ScpActionDefinition?: ScpActionDefinition;
  SsmActionDefinition?: SsmActionDefinition;
}

export interface AWS_EMR_InstanceGroupConfig____CloudWatchAlarmDefinition {
  ComparisonOperator: string;
  Dimensions?: Array<AWS_EMR_InstanceGroupConfig____MetricDimension>;
  EvaluationPeriods?: number;
  MetricName: string;
  Namespace?: string;
  Period: number;
  Statistic?: string;
  Threshold: number;
  Unit?: string;
}

export interface AWS_WAFv2_WebACL____SizeConstraintStatement {
  FieldToMatch: AWS_WAFv2_WebACL____FieldToMatch;
  ComparisonOperator: string;
  Size: number;
  TextTransformations: Array<AWS_WAFv2_WebACL____TextTransformation>;
}

export interface AWS_EMR_Cluster____EbsConfiguration {
  EbsBlockDeviceConfigs?: Array<AWS_EMR_Cluster____EbsBlockDeviceConfig>;
  EbsOptimized?: boolean;
}

export interface AWS_S3_Bucket____DataExport {
  Destination: AWS_S3_Bucket____Destination;
  OutputSchemaVersion: string;
}

export interface CustomErrorResponse {
  ErrorCachingMinTTL?: number;
  ErrorCode: number;
  ResponseCode?: number;
  ResponsePagePath?: string;
}

export interface InstancesDistribution {
  OnDemandAllocationStrategy?: string;
  OnDemandBaseCapacity?: number;
  OnDemandPercentageAboveBaseCapacity?: number;
  SpotAllocationStrategy?: string;
  SpotInstancePools?: number;
  SpotMaxPrice?: string;
}

export interface AWS_Lambda_EventInvokeConfig____DestinationConfig {
  OnSuccess?: OnSuccess;
  OnFailure?: AWS_Lambda_EventInvokeConfig____OnFailure;
}

export interface AWS_ElasticLoadBalancingV2_LoadBalancer____SubnetMapping {
  AllocationId?: string;
  IPv6Address?: string;
  PrivateIPv4Address?: string;
  SubnetId: string;
}

export interface RuleDefinition {
  MatchAttributes: MatchAttributes;
  Actions: Array<string>;
}

export interface NotebookInstanceLifecycleHook {
  Content?: string;
}

export interface AWS_AppMesh_VirtualGateway____SubjectAlternativeNameMatchers {
  Exact?: Array<string>;
}

export interface AccessLogSettings {
  Format?: string;
  DestinationArn?: string;
}

export interface AWS_EC2_CapacityReservation____TagSpecification {
  ResourceType?: string;
  Tags?: Array<Tag>;
}

export interface AWS_KinesisAnalytics_Application____InputParallelism {
  Count?: number;
}

export interface ComponentDependencyRequirement {
  VersionRequirement?: string;
  DependencyType?: string;
}

export interface PathComponent {
  SequenceNumber?: number;
  AclRule?: AnalysisAclRule;
  Component?: AnalysisComponent;
  DestinationVpc?: AnalysisComponent;
  OutboundHeader?: AnalysisPacketHeader;
  InboundHeader?: AnalysisPacketHeader;
  RouteTableRoute?: AnalysisRouteTableRoute;
  SecurityGroupRule?: AnalysisSecurityGroupRule;
  SourceVpc?: AnalysisComponent;
  Subnet?: AnalysisComponent;
  Vpc?: AnalysisComponent;
}

export interface AWS_NetworkFirewall_RuleGroup____RuleGroup {
  RuleVariables?: RuleVariables;
  RulesSource: RulesSource;
}

export interface AWS_ECS_TaskDefinition____PortMapping {
  ContainerPort?: number;
  HostPort?: number;
  Protocol?: string;
}

export interface AWS_EC2_LaunchTemplate____CpuOptions {
  ThreadsPerCore?: number;
  CoreCount?: number;
}

export interface AWS_WAFRegional_SizeConstraintSet____FieldToMatch {
  Type: string;
  Data?: string;
}

export interface VirtualNodeSpec {
  Logging?: AWS_AppMesh_VirtualNode____Logging;
  Backends?: Array<Backend>;
  Listeners?: Array<Listener>;
  BackendDefaults?: BackendDefaults;
  ServiceDiscovery?: ServiceDiscovery;
}

export interface ModelBiasAppSpecification {
  ImageUri: string;
  ConfigUri: string;
  Environment?: AWS_SageMaker_ModelBiasJobDefinition____Environment;
}

export interface AWS_ECS_TaskDefinition____Ulimit {
  HardLimit: number;
  Name: string;
  SoftLimit: number;
}

export interface AWS_ElastiCache_ReplicationGroup____DestinationDetails {
  CloudWatchLogsDetails?: AWS_ElastiCache_ReplicationGroup____CloudWatchLogsDestinationDetails;
  KinesisFirehoseDetails?: AWS_ElastiCache_ReplicationGroup____KinesisFirehoseDestinationDetails;
}

export interface KubernetesNetworkConfig {
  ServiceIpv4Cidr?: string;
}

export interface ProvisioningPreferences {
  StackSetAccounts?: Array<string>;
  StackSetFailureToleranceCount?: number;
  StackSetFailureTolerancePercentage?: number;
  StackSetMaxConcurrencyCount?: number;
  StackSetMaxConcurrencyPercentage?: number;
  StackSetOperationType?: string;
  StackSetRegions?: Array<string>;
}

export interface GrpcRouteAction {
  WeightedTargets: Array<WeightedTarget>;
}

export interface AWS_Lambda_Function____Environment {
  Variables?: Record<string, string>;
}

export interface AWS_WAFv2_WebACL____FieldToMatch {
  SingleHeader?: any;
  SingleQueryArgument?: any;
  AllQueryArguments?: any;
  UriPath?: any;
  QueryString?: any;
  Body?: any;
  Method?: any;
  JsonBody?: AWS_WAFv2_WebACL____JsonBody;
}

export interface Serializer {
  OrcSerDe?: OrcSerDe;
  ParquetSerDe?: ParquetSerDe;
}

export interface AWS_WAFv2_WebACL____SqliMatchStatement {
  FieldToMatch: AWS_WAFv2_WebACL____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_WebACL____TextTransformation>;
}

export interface GrpcRouteMatch {
  ServiceName?: string;
  Metadata?: Array<GrpcRouteMetadata>;
  MethodName?: string;
}

export interface ReplicationTimeValue {
  Minutes: number;
}

export interface AWS_CloudFront_StreamingDistribution____Logging {
  Bucket: string;
  Enabled: boolean;
  Prefix: string;
}

export interface AWS_SSM_MaintenanceWindowTarget____Targets {
  Values: Array<string>;
  Key: string;
}

export interface UpsolverDestinationProperties {
  BucketName: string;
  BucketPrefix?: string;
  S3OutputFormatConfig: UpsolverS3OutputFormatConfig;
}

export interface JsonClassifier {
  JsonPath: string;
  Name?: string;
}

export interface AnalysisComponent {
  Id?: string;
  Arn?: string;
}

export interface Listener {
  ConnectionPool?: VirtualNodeConnectionPool;
  Timeout?: ListenerTimeout;
  HealthCheck?: AWS_AppMesh_VirtualNode____HealthCheck;
  TLS?: ListenerTls;
  PortMapping: AWS_AppMesh_VirtualNode____PortMapping;
  OutlierDetection?: OutlierDetection;
}

export interface AWS_WAFv2_WebACL____GeoMatchStatement {
  CountryCodes?: Array<string>;
  ForwardedIPConfig?: AWS_WAFv2_WebACL____ForwardedIPConfiguration;
}

export interface CopyCommand {
  CopyOptions?: string;
  DataTableColumns?: string;
  DataTableName: string;
}

export interface AWS_AppConfig_Environment____Tags {
  Value?: string;
  Key?: string;
}

export interface ProjectTriggers {
  FilterGroups?: Array<FilterGroup>;
  BuildType?: string;
  Webhook?: boolean;
}

export interface ApiPassthrough {
  Extensions?: Extensions;
  Subject?: AWS_ACMPCA_Certificate____Subject;
}

export interface VirtualServiceProvider {
  VirtualNode?: VirtualNodeServiceProvider;
  VirtualRouter?: VirtualRouterServiceProvider;
}

export interface AWS_ApiGatewayV2_DomainName____MutualTlsAuthentication {
  TruststoreVersion?: string;
  TruststoreUri?: string;
}

export interface HostHeaderConfig {
  Values?: Array<string>;
}

export interface AWS_WAFv2_RuleGroup____VisibilityConfig {
  SampledRequestsEnabled: boolean;
  CloudWatchMetricsEnabled: boolean;
  MetricName: string;
}

export interface AWS_IoTAnalytics_Dataset____S3DestinationConfiguration {
  GlueConfiguration?: GlueConfiguration;
  Bucket: string;
  Key: string;
  RoleArn: string;
}

export interface AWS_Synthetics_Canary____Schedule {
  Expression: string;
  DurationInSeconds?: string;
}

export interface HealthCheckConfig {
  Type: string;
  ResourcePath?: string;
  FailureThreshold?: number;
}

export interface IbmDb2Settings {
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface OpenXJsonSerDe {
  CaseInsensitive?: boolean;
  ColumnToJsonKeyMappings?: Record<string, string>;
  ConvertDotsInJsonKeysToUnderscores?: boolean;
}

export interface CFNDataSourceConfigurations {
  S3Logs?: CFNS3LogsConfiguration;
}

export interface DnsServiceDiscovery {
  Hostname: string;
}

export type S3Encryptions = S3Encryption[];

export interface AWS_ACMPCA_CertificateAuthority____EdiPartyName {
  PartyName: string;
  NameAssigner: string;
}

export interface AWS_ACMPCA_Certificate____EdiPartyName {
  PartyName: string;
  NameAssigner: string;
}

export interface AWS_SageMaker_MonitoringSchedule____ClusterConfig {
  InstanceCount: number;
  InstanceType: string;
  VolumeKmsKeyId?: string;
  VolumeSizeInGB: number;
}

export interface ContainerDependency {
  ContainerName?: string;
  Condition?: string;
}

export interface AWS_WAFv2_RuleGroup____GeoMatchStatement {
  CountryCodes?: Array<string>;
  ForwardedIPConfig?: AWS_WAFv2_RuleGroup____ForwardedIPConfiguration;
}

export interface BatchArrayProperties {
  Size?: number;
}

export interface StreamEncryption {
  EncryptionType: string;
  KeyId: string;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____NetworkConfig {
  EnableInterContainerTrafficEncryption?: boolean;
  EnableNetworkIsolation?: boolean;
  VpcConfig?: AWS_SageMaker_ModelQualityJobDefinition____VpcConfig;
}

export interface Ec2Config {
  SecurityGroupArns: Array<string>;
  SubnetArn: string;
}

export interface AWS_WAFv2_RuleGroup____AndStatement {
  Statements: Array<AWS_WAFv2_RuleGroup____Statement>;
}

export interface AWS_QuickSight_Dashboard____IntegerParameter {
  Values: Array<number>;
  Name: string;
}

export interface StreamingDistributionConfig {
  Logging?: AWS_CloudFront_StreamingDistribution____Logging;
  Comment: string;
  PriceClass?: string;
  S3Origin: S3Origin;
  Enabled: boolean;
  Aliases?: Array<string>;
  TrustedSigners: TrustedSigners;
}

export interface VirtualGatewayClientPolicy {
  TLS?: VirtualGatewayClientPolicyTls;
}

export interface AWS_EMR_Cluster____InstanceTypeConfig {
  BidPrice?: string;
  BidPriceAsPercentageOfOnDemandPrice?: number;
  Configurations?: Array<AWS_EMR_Cluster____Configuration>;
  EbsConfiguration?: AWS_EMR_Cluster____EbsConfiguration;
  InstanceType: string;
  WeightedCapacity?: number;
}

export interface AWS_SageMaker_Model____ContainerDefinition {
  ImageConfig?: AWS_SageMaker_Model____ImageConfig;
  ContainerHostname?: string;
  ModelPackageName?: string;
  Mode?: string;
  Environment?: any;
  ModelDataUrl?: string;
  Image?: string;
  MultiModelConfig?: MultiModelConfig;
}

export interface MonitoringAppSpecification {
  ContainerArguments?: Array<string>;
  ContainerEntrypoint?: Array<string>;
  ImageUri: string;
  PostAnalyticsProcessorSourceUri?: string;
  RecordPreprocessorSourceUri?: string;
}

export interface ConnectionPasswordEncryption {
  ReturnConnectionPasswordEncrypted?: boolean;
  KmsKeyId?: string;
}

export interface ServiceNowSourceProperties {
  Object: string;
}

export interface TlsValidationContextFileTrust {
  CertificateChain: string;
}

export interface MaintenanceWindowStepFunctionsParameters {
  Input?: string;
  Name?: string;
}

export interface InviteMessageTemplate {
  EmailMessage?: string;
  SMSMessage?: string;
  EmailSubject?: string;
}

export interface AWS_EMR_Cluster____MetricDimension {
  Key: string;
  Value: string;
}

export interface AppFlowConfig {
  RoleArn: string;
  FlowName: string;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____ReferenceSchema {
  RecordEncoding?: string;
  RecordColumns: Array<AWS_KinesisAnalytics_ApplicationReferenceDataSource____RecordColumn>;
  RecordFormat: AWS_KinesisAnalytics_ApplicationReferenceDataSource____RecordFormat;
}

export interface Prometheus {
  JmxExporter?: JmxExporter;
  NodeExporter?: NodeExporter;
}

export interface AWS_Greengrass_ConnectorDefinition____Connector {
  ConnectorArn: string;
  Parameters?: any;
  Id: string;
}

export interface AWS_S3_Bucket____FilterRule {
  Name: string;
  Value: string;
}

export interface VPC {
  VPCId: string;
  VPCRegion: string;
}

export interface TeradataParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface AWS_ElasticLoadBalancingV2_Listener____TargetGroupStickinessConfig {
  Enabled?: boolean;
  DurationSeconds?: number;
}

export interface AttributePayload {
  Attributes?: Record<string, string>;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____SecretsManagerSecretResourceData {
  ARN: string;
  AdditionalStagingLabelsToDownload?: Array<string>;
}

export interface TimePeriod {
  Start?: string;
  End?: string;
}

export interface AWS_DLM_LifecyclePolicy____EncryptionConfiguration {
  Encrypted: boolean;
  CmkArn?: string;
}

export interface PlayerLatencyPolicy {
  PolicyDurationSeconds?: number;
  MaximumIndividualPlayerLatencyMilliseconds?: number;
}

export interface AWS_EC2_Instance____BlockDeviceMapping {
  DeviceName: string;
  Ebs?: AWS_EC2_Instance____Ebs;
  NoDevice?: NoDevice;
  VirtualName?: string;
}

export interface GeoMatchConstraint {
  Type: string;
  Value: string;
}

export interface Options {
  Atime?: string;
  BytesPerSecond?: number;
  Gid?: string;
  LogLevel?: string;
  Mtime?: string;
  OverwriteMode?: string;
  PosixPermissions?: string;
  PreserveDeletedFiles?: string;
  PreserveDevices?: string;
  TaskQueueing?: string;
  TransferMode?: string;
  Uid?: string;
  VerifyMode?: string;
}

export interface HttpRoute {
  Action: HttpRouteAction;
  Timeout?: AWS_AppMesh_Route____HttpTimeout;
  RetryPolicy?: HttpRetryPolicy;
  Match: HttpRouteMatch;
}

export interface AWS_QuickSight_Theme____ResourcePermission {
  Actions: Array<string>;
  Principal: string;
}

export interface ResultConfigurationUpdates {
  EncryptionConfiguration?: AWS_Athena_WorkGroup____EncryptionConfiguration;
  OutputLocation?: string;
  RemoveEncryptionConfiguration?: boolean;
  RemoveOutputLocation?: boolean;
}

export interface AWS_IoTEvents_DetectorModel____Action {
  ClearTimer?: ClearTimer;
  DynamoDB?: DynamoDB;
  DynamoDBv2?: DynamoDBv2;
  Firehose?: AWS_IoTEvents_DetectorModel____Firehose;
  IotEvents?: IotEvents;
  IotSiteWise?: IotSiteWise;
  IotTopicPublish?: IotTopicPublish;
  Lambda?: AWS_IoTEvents_DetectorModel____Lambda;
  ResetTimer?: ResetTimer;
  SetTimer?: SetTimer;
  SetVariable?: SetVariable;
  Sns?: Sns;
  Sqs?: Sqs;
}

export interface CloudwatchMetricAction {
  MetricName: string;
  MetricValue: string;
  MetricNamespace: string;
  MetricUnit: string;
  RoleArn: string;
  MetricTimestamp?: string;
}

export interface AWS_Greengrass_SubscriptionDefinitionVersion____Subscription {
  Target: string;
  Id: string;
  Source: string;
  Subject: string;
}

export interface AWS_WAFRegional_SqlInjectionMatchSet____FieldToMatch {
  Type: string;
  Data?: string;
}

export interface AWS_NetworkFirewall_FirewallPolicy____ActionDefinition {
  PublishMetricAction?: AWS_NetworkFirewall_FirewallPolicy____PublishMetricAction;
}

export interface AWS_KinesisAnalytics_ApplicationOutput____LambdaOutput {
  ResourceARN: string;
  RoleARN: string;
}

export interface TemplateSourceTemplate {
  Arn: string;
}

export interface ExcelOptions {
  SheetNames?: Array<string>;
  SheetIndexes?: Array<number>;
  HeaderRow?: boolean;
}

export interface AutoRollbackConfiguration {
  Enabled?: boolean;
  Events?: Array<string>;
}

export interface WindowsEvent {
  LogGroupName: string;
  EventName: string;
  EventLevels: Array<string>;
  PatternSet?: string;
}

export interface AWS_SageMaker_UserProfile____KernelGatewayAppSettings {
  CustomImages?: Array<AWS_SageMaker_UserProfile____CustomImage>;
  DefaultResourceSpec?: AWS_SageMaker_UserProfile____ResourceSpec;
}

export interface DeploymentConfig {
  AutoRollbackConfiguration?: AutoRollbackConfig;
  BlueGreenUpdatePolicy: BlueGreenUpdatePolicy;
}

export interface ScpActionDefinition {
  PolicyId: string;
  TargetIds: Array<string>;
}

export interface ReplicationRuleAndOperator {
  Prefix?: string;
  TagFilters?: Array<AWS_S3_Bucket____TagFilter>;
}

export interface AWS_CodeBuild_Project____Source {
  Type: string;
  ReportBuildStatus?: boolean;
  Auth?: SourceAuth;
  SourceIdentifier?: string;
  BuildSpec?: string;
  GitCloneDepth?: number;
  BuildStatusConfig?: BuildStatusConfig;
  GitSubmodulesConfig?: GitSubmodulesConfig;
  InsecureSsl?: boolean;
  Location?: string;
}

export interface AWS_EC2_Instance____PrivateIpAddressSpecification {
  Primary: boolean;
  PrivateIpAddress: string;
}

export interface SocketAddress {
  Name?: string;
  Port?: number;
}

export interface AWS_EC2_EC2Fleet____TagSpecification {
  ResourceType?: string;
  Tags?: Array<Tag>;
}

export interface CodeSigningPolicies {
  UntrustedArtifactOnDeployment: string;
}

export interface HostVolumeProperties {
  SourcePath?: string;
}

export interface AWS_IAM_User____Policy {
  PolicyDocument: any;
  PolicyName: string;
}

export interface AWS_EMR_Cluster____OnDemandProvisioningSpecification {
  AllocationStrategy: string;
}

export interface MetricSource {
  S3SourceConfig?: S3SourceConfig;
  RDSSourceConfig?: RDSSourceConfig;
  RedshiftSourceConfig?: RedshiftSourceConfig;
  CloudwatchConfig?: CloudwatchConfig;
  AppFlowConfig?: AppFlowConfig;
}

export interface BatchParameters {
  ArrayProperties?: BatchArrayProperties;
  JobDefinition: string;
  JobName: string;
  RetryStrategy?: BatchRetryStrategy;
}

export interface TimeBasedAutoScaling {
  Friday?: Record<string, string>;
  Monday?: Record<string, string>;
  Saturday?: Record<string, string>;
  Sunday?: Record<string, string>;
  Thursday?: Record<string, string>;
  Tuesday?: Record<string, string>;
  Wednesday?: Record<string, string>;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____MonitoringGroundTruthS3Input {
  S3Uri: string;
}

export interface SpotOptionsRequest {
  SingleAvailabilityZone?: boolean;
  AllocationStrategy?: string;
  SingleInstanceType?: boolean;
  MinTargetCapacity?: number;
  MaxTotalPrice?: string;
  InstanceInterruptionBehavior?: string;
  InstancePoolsToUseCount?: number;
}

export interface MetricStreamFilter {
  Namespace: string;
}

export interface ElasticsearchSettings {
  EndpointUri?: string;
  FullLoadErrorPercentage?: number;
  ErrorRetryDuration?: number;
  ServiceAccessRoleArn?: string;
}

export interface InputRecordTables {
  GlueTables?: Array<GlueTables>;
}

export interface AppCookieStickinessPolicy {
  CookieName: string;
  PolicyName: string;
}

export interface MarginStyle {
  Show?: boolean;
}

export interface ExportToCSVOption {
  AvailabilityStatus?: string;
}

export interface VersionWeight {
  FunctionVersion: string;
  FunctionWeight: number;
}

export interface GlueTables {
  ConnectionName?: string;
  TableName: string;
  DatabaseName: string;
  CatalogId?: string;
}

export interface AWS_IoTAnalytics_Channel____ServiceManagedS3 {}

export interface AdvancedBackupSettingResourceType {
  BackupOptions: any;
  ResourceType: string;
}

export interface AutoBranchCreationConfig {
  EnvironmentVariables?: Array<AWS_Amplify_App____EnvironmentVariable>;
  EnableAutoBranchCreation?: boolean;
  PullRequestEnvironmentName?: string;
  AutoBranchCreationPatterns?: Array<string>;
  EnablePullRequestPreview?: boolean;
  EnableAutoBuild?: boolean;
  EnablePerformanceMode?: boolean;
  BuildSpec?: string;
  Stage?: string;
  BasicAuthConfig?: AWS_Amplify_App____BasicAuthConfig;
}

export interface AWS_MSK_Cluster____LoggingInfo {
  BrokerLogs: BrokerLogs;
}

export interface TcpRouteAction {
  WeightedTargets: Array<WeightedTarget>;
}

export interface AWS_EMR_Cluster____ScalingTrigger {
  CloudWatchAlarmDefinition: AWS_EMR_Cluster____CloudWatchAlarmDefinition;
}

export interface RepositoryCredentials {
  CredentialsParameter?: string;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____S3Output {
  LocalPath: string;
  S3UploadMode?: string;
  S3Uri: string;
}

export interface OrcSerDe {
  BlockSizeBytes?: number;
  BloomFilterColumns?: Array<string>;
  BloomFilterFalsePositiveProbability?: number;
  Compression?: string;
  DictionaryKeyThreshold?: number;
  EnablePadding?: boolean;
  FormatVersion?: string;
  PaddingTolerance?: number;
  RowIndexStride?: number;
  StripeSizeBytes?: number;
}

export type AWS_SageMaker_DataQualityJobDefinition____Environment = undefined;

export interface AWS_ElasticLoadBalancingV2_ListenerCertificate____Certificate {
  CertificateArn?: string;
}

export interface AWS_AppMesh_VirtualNode____GrpcTimeout {
  PerRequest?: AWS_AppMesh_VirtualNode____Duration;
  Idle?: AWS_AppMesh_VirtualNode____Duration;
}

export interface InputArtifact {
  Name: string;
}

export interface SkillPackage {
  S3BucketRole?: string;
  S3ObjectVersion?: string;
  S3Bucket: string;
  S3Key: string;
  Overrides?: Overrides;
}

export interface VirtualNodeConnectionPool {
  TCP?: VirtualNodeTcpConnectionPool;
  HTTP2?: VirtualNodeHttp2ConnectionPool;
  HTTP?: VirtualNodeHttpConnectionPool;
  GRPC?: VirtualNodeGrpcConnectionPool;
}

export interface BucketEncryption {
  ServerSideEncryptionConfiguration: Array<ServerSideEncryptionRule>;
}

export interface LdapServerMetadata {
  Hosts: Array<string>;
  UserRoleName?: string;
  UserSearchMatching: string;
  RoleName?: string;
  UserBase: string;
  UserSearchSubtree?: boolean;
  RoleSearchMatching: string;
  ServiceAccountUsername: string;
  RoleBase: string;
  ServiceAccountPassword: string;
  RoleSearchSubtree?: boolean;
}

export interface Metrics {
  EventThreshold?: ReplicationTimeValue;
  Status: string;
}

export interface AthenaParameters {
  WorkGroup?: string;
}

export interface AWS_ACMPCA_CertificateAuthority____Subject {
  Country?: string;
  Organization?: string;
  OrganizationalUnit?: string;
  DistinguishedNameQualifier?: string;
  State?: string;
  CommonName?: string;
  SerialNumber?: string;
  Locality?: string;
  Title?: string;
  Surname?: string;
  GivenName?: string;
  Initials?: string;
  Pseudonym?: string;
  GenerationQualifier?: string;
}

export interface GutterStyle {
  Show?: boolean;
}

export interface RunCommandParameters {
  RunCommandTargets: Array<RunCommandTarget>;
}

export interface DomainValidationOption {
  DomainName: string;
  HostedZoneId?: string;
  ValidationDomain?: string;
}

export interface AWS_WAFv2_WebACL____RuleAction {
  Allow?: AllowAction;
  Block?: BlockAction;
  Count?: CountAction;
}

export interface RoutingRuleCondition {
  HttpErrorCodeReturnedEquals?: string;
  KeyPrefixEquals?: string;
}

export interface AWS_AppMesh_VirtualNode____Logging {
  AccessLog?: AccessLog;
}

export interface DataQualityJobInput {
  EndpointInput: AWS_SageMaker_DataQualityJobDefinition____EndpointInput;
}

export interface AWS_S3_Bucket____LifecycleConfiguration {
  Rules: Array<AWS_S3_Bucket____Rule>;
}

export interface ManifestFileLocation {
  Bucket: string;
  Key: string;
}

export interface AWS_Glue_Partition____SerdeInfo {
  Parameters?: any;
  SerializationLibrary?: string;
  Name?: string;
}

export interface CapacitySize {
  Type: string;
  Value: number;
}

export interface VirtualRouterListener {
  PortMapping: AWS_AppMesh_VirtualRouter____PortMapping;
}

export interface ProjectSourceVersion {
  SourceIdentifier: string;
  SourceVersion?: string;
}

export interface FilterOperation {
  ConditionExpression: string;
}

export interface AWS_NetworkFirewall_Firewall____SubnetMapping {
  SubnetId: string;
}

export interface AWS_CodeCommit_Repository____Code {
  S3: AWS_CodeCommit_Repository____S3;
  BranchName?: string;
}

export interface DeploymentCanarySettings {
  PercentTraffic?: number;
  StageVariableOverrides?: Record<string, string>;
  UseStageCache?: boolean;
}

export interface TokenValidityUnits {
  IdToken?: string;
  RefreshToken?: string;
  AccessToken?: string;
}

export interface AWS_EMR_InstanceGroupConfig____EbsBlockDeviceConfig {
  VolumeSpecification: AWS_EMR_InstanceGroupConfig____VolumeSpecification;
  VolumesPerInstance?: number;
}

export interface AWS_CodeDeploy_DeploymentGroup____S3Location {
  Bucket: string;
  BundleType?: string;
  ETag?: string;
  Key: string;
  Version?: string;
}

export interface AWS_MediaConnect_FlowEntitlement____Encryption {
  Algorithm: string;
  ConstantInitializationVector?: string;
  DeviceId?: string;
  KeyType?: string;
  Region?: string;
  ResourceId?: string;
  RoleArn: string;
  SecretArn?: string;
  Url?: string;
}

export interface AWS_WAFv2_RuleGroup____IPSetForwardedIPConfiguration {
  HeaderName: string;
  FallbackBehavior: string;
  Position: string;
}

export interface AWS_ECS_TaskSet____LoadBalancer {
  ContainerName?: string;
  ContainerPort?: number;
  LoadBalancerName?: string;
  TargetGroupArn?: string;
}

export interface AWS_Config_OrganizationConformancePack____ConformancePackInputParameter {
  ParameterName: string;
  ParameterValue: string;
}

export interface PrivateIpAdd {
  PrivateIpAddress?: string;
  Primary?: boolean;
}

export interface VirtualGatewayTlsValidationContextSdsTrust {
  SecretName: string;
}

export interface AWS_GameLift_GameSessionQueue____Destination {
  DestinationArn?: string;
}

export interface ZendeskConnectorProfileCredentials {
  ClientId: string;
  ClientSecret: string;
  AccessToken?: string;
  ConnectorOAuthRequest?: ConnectorOAuthRequest;
}

export interface LambdaFunctionAssociation {
  EventType?: string;
  IncludeBody?: boolean;
  LambdaFunctionARN?: string;
}

export interface ElasticsearchBufferingHints {
  IntervalInSeconds?: number;
  SizeInMBs?: number;
}

export interface ExecuteCommandLogConfiguration {
  CloudWatchLogGroupName?: string;
  CloudWatchEncryptionEnabled?: boolean;
  S3BucketName?: string;
  S3EncryptionEnabled?: boolean;
  S3KeyPrefix?: string;
}

export interface AWS_Batch_ComputeEnvironment____LaunchTemplateSpecification {
  LaunchTemplateName?: string;
  Version?: string;
  LaunchTemplateId?: string;
}

export interface DataColorPalette {
  EmptyFillColor?: string;
  Colors?: Array<string>;
  MinMaxGradient?: Array<string>;
}

export interface LifecycleHookSpecification {
  DefaultResult?: string;
  HeartbeatTimeout?: number;
  LifecycleHookName: string;
  LifecycleTransition: string;
  NotificationMetadata?: string;
  NotificationTargetARN?: string;
  RoleARN?: string;
}

export interface UplinkSpectrumConfig {
  CenterFrequency?: Frequency;
  Polarization?: string;
}

export interface ExperimentTemplateTarget {
  ResourceType: string;
  ResourceArns?: Array<string>;
  ResourceTags?: Record<string, string>;
  Filters?: Array<ExperimentTemplateTargetFilter>;
  SelectionMode: string;
}

export interface ContainerInfo {
  EksInfo: EksInfo;
}

export interface EncryptionOptions {
  KmsKeyId?: string;
  UseAwsOwnedKey: boolean;
}

export interface S3Action {
  BucketName: string;
  Key: string;
  RoleArn: string;
  CannedAcl?: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationOutput____LambdaOutput {
  ResourceARN: string;
}

export interface SchemaDefinition {
  Columns?: Array<AWS_IoTAnalytics_Datastore____Column>;
}

export interface LogsConfig {
  CloudWatchLogs?: CloudWatchLogsConfig;
  S3Logs?: S3LogsConfig;
}

export interface WorkGroupConfiguration {
  BytesScannedCutoffPerQuery?: number;
  EnforceWorkGroupConfiguration?: boolean;
  PublishCloudWatchMetricsEnabled?: boolean;
  RequesterPaysEnabled?: boolean;
  ResultConfiguration?: ResultConfiguration;
  EngineVersion?: EngineVersion;
}

export interface EncryptionInfo {
  EncryptionAtRest?: AWS_MSK_Cluster____EncryptionAtRest;
  EncryptionInTransit?: EncryptionInTransit;
}

export interface MemberConfiguration {
  Description?: string;
  MemberFrameworkConfiguration?: MemberFrameworkConfiguration;
  Name: string;
}

export interface SplunkDestinationConfiguration {
  CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
  HECAcknowledgmentTimeoutInSeconds?: number;
  HECEndpoint: string;
  HECEndpointType: string;
  HECToken: string;
  ProcessingConfiguration?: ProcessingConfiguration;
  RetryOptions?: SplunkRetryOptions;
  S3BackupMode?: string;
  S3Configuration: AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration;
}

export interface RecipeParameters {
  AggregateFunction?: string;
  Base?: string;
  CaseStatement?: string;
  CategoryMap?: string;
  CharsToRemove?: string;
  CollapseConsecutiveWhitespace?: string;
  ColumnDataType?: string;
  ColumnRange?: string;
  Count?: string;
  CustomCharacters?: string;
  CustomStopWords?: string;
  CustomValue?: string;
  DatasetsColumns?: string;
  DateAddValue?: string;
  DateTimeFormat?: string;
  DateTimeParameters?: string;
  DeleteOtherRows?: string;
  Delimiter?: string;
  EndPattern?: string;
  EndPosition?: string;
  EndValue?: string;
  ExpandContractions?: string;
  Exponent?: string;
  FalseString?: string;
  GroupByAggFunctionOptions?: string;
  GroupByColumns?: string;
  HiddenColumns?: string;
  IgnoreCase?: string;
  IncludeInSplit?: string;
  Interval?: string;
  IsText?: string;
  JoinKeys?: string;
  JoinType?: string;
  LeftColumns?: string;
  Limit?: string;
  LowerBound?: string;
  MapType?: string;
  ModeType?: string;
  MultiLine?: boolean;
  NumRows?: string;
  NumRowsAfter?: string;
  NumRowsBefore?: string;
  OrderByColumn?: string;
  OrderByColumns?: string;
  Other?: string;
  Pattern?: string;
  PatternOption1?: string;
  PatternOption2?: string;
  PatternOptions?: string;
  Period?: string;
  Position?: string;
  RemoveAllPunctuation?: string;
  RemoveAllQuotes?: string;
  RemoveAllWhitespace?: string;
  RemoveCustomCharacters?: string;
  RemoveCustomValue?: string;
  RemoveLeadingAndTrailingPunctuation?: string;
  RemoveLeadingAndTrailingQuotes?: string;
  RemoveLeadingAndTrailingWhitespace?: string;
  RemoveLetters?: string;
  RemoveNumbers?: string;
  RemoveSourceColumn?: string;
  RemoveSpecialCharacters?: string;
  RightColumns?: string;
  SampleSize?: string;
  SampleType?: string;
  SecondInput?: string;
  SecondaryInputs?: Array<SecondaryInput>;
  SourceColumn?: string;
  SourceColumn1?: string;
  SourceColumn2?: string;
  SourceColumns?: string;
  StartColumnIndex?: string;
  StartPattern?: string;
  StartPosition?: string;
  StartValue?: string;
  StemmingMode?: string;
  StepCount?: string;
  StepIndex?: string;
  StopWordsMode?: string;
  Strategy?: string;
  SheetNames?: Array<string>;
  SheetIndexes?: Array<number>;
  TargetColumn?: string;
  TargetColumnNames?: string;
  TargetDateFormat?: string;
  TargetIndex?: string;
  TimeZone?: string;
  TokenizerPattern?: string;
  TrueString?: string;
  UdfLang?: string;
  Units?: string;
  UnpivotColumn?: string;
  UpperBound?: string;
  UseNewDataFrame?: string;
  Value?: string;
  Value1?: string;
  Value2?: string;
  ValueColumn?: string;
  ViewFrame?: string;
  Input?: any;
}

export interface LocationConfiguration {
  Location: string;
  LocationCapacity?: LocationCapacity;
}

export interface AWS_Greengrass_FunctionDefinition____Execution {
  IsolationMode?: string;
  RunAs?: AWS_Greengrass_FunctionDefinition____RunAs;
}

export interface ResourceTag {
  Key: string;
  Value?: string;
}

export interface CognitoMemberDefinition {
  CognitoUserPool: string;
  CognitoClientId: string;
  CognitoUserGroup: string;
}

export interface S3Encryption {
  KmsKeyArn?: string;
  S3EncryptionMode?: string;
}

export interface GrpcRetryPolicy {
  MaxRetries: number;
  PerRetryTimeout: AWS_AppMesh_Route____Duration;
  GrpcRetryEvents?: Array<string>;
  HttpRetryEvents?: Array<string>;
  TcpRetryEvents?: Array<string>;
}

export interface Frequency {
  Value?: number;
  Units?: string;
}

export interface ApprovalThresholdPolicy {
  ThresholdComparator?: string;
  ThresholdPercentage?: number;
  ProposalDurationInHours?: number;
}

export interface AWS_WAF_SqlInjectionMatchSet____SqlInjectionMatchTuple {
  FieldToMatch: AWS_WAF_SqlInjectionMatchSet____FieldToMatch;
  TextTransformation: string;
}

export interface AWS_Greengrass_ResourceDefinition____SageMakerMachineLearningModelResourceData {
  OwnerSetting?: AWS_Greengrass_ResourceDefinition____ResourceDownloadOwnerSetting;
  DestinationPath: string;
  SageMakerJobArn: string;
}

export interface TargetGroupAttribute {
  Key?: string;
  Value?: string;
}

export interface AWS_SageMaker_Domain____ResourceSpec {
  InstanceType?: string;
  SageMakerImageArn?: string;
  SageMakerImageVersionArn?: string;
}

export interface AWS_WAFv2_WebACL____JsonBody {
  MatchPattern: AWS_WAFv2_WebACL____JsonMatchPattern;
  MatchScope: string;
  InvalidFallbackBehavior?: string;
}

export interface JsonOptions {
  MultiLine?: boolean;
}

export interface AWS_RDS_DBSecurityGroup____Ingress {
  CIDRIP?: string;
  EC2SecurityGroupId?: string;
  EC2SecurityGroupName?: string;
  EC2SecurityGroupOwnerId?: string;
}

export interface ServiceDiscovery {
  DNS?: DnsServiceDiscovery;
  AWSCloudMap?: AwsCloudMapServiceDiscovery;
}

export interface AWS_CloudFront_OriginRequestPolicy____CookiesConfig {
  CookieBehavior: string;
  Cookies?: Array<string>;
}

export interface SsmActionDefinition {
  Subtype: string;
  Region: string;
  InstanceIds: Array<string>;
}

export interface AWS_IoTEvents_DetectorModel____AssetPropertyTimestamp {
  OffsetInNanos?: string;
  TimeInSeconds: string;
}

export interface BackupPolicy {
  Status: string;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____NetworkConfig {
  EnableInterContainerTrafficEncryption?: boolean;
  EnableNetworkIsolation?: boolean;
  VpcConfig?: AWS_SageMaker_ModelExplainabilityJobDefinition____VpcConfig;
}

export interface AWS_EMR_InstanceFleetConfig____SpotProvisioningSpecification {
  AllocationStrategy?: string;
  BlockDurationMinutes?: number;
  TimeoutAction: string;
  TimeoutDurationMinutes: number;
}

export interface AWS_AutoScaling_AutoScalingGroup____LaunchTemplateSpecification {
  LaunchTemplateId?: string;
  LaunchTemplateName?: string;
  Version: string;
}

export interface AWS_Neptune_DBCluster____DBClusterRole {
  RoleArn: string;
  FeatureName?: string;
}

export interface ContainerProperties {
  User?: string;
  Secrets?: Array<AWS_Batch_JobDefinition____Secret>;
  Memory?: number;
  Privileged?: boolean;
  LinuxParameters?: AWS_Batch_JobDefinition____LinuxParameters;
  FargatePlatformConfiguration?: FargatePlatformConfiguration;
  JobRoleArn?: string;
  ReadonlyRootFilesystem?: boolean;
  Vcpus?: number;
  Image: string;
  ResourceRequirements?: Array<AWS_Batch_JobDefinition____ResourceRequirement>;
  LogConfiguration?: AWS_Batch_JobDefinition____LogConfiguration;
  MountPoints?: Array<MountPoints>;
  ExecutionRoleArn?: string;
  Volumes?: Array<Volumes>;
  Command?: Array<string>;
  Environment?: Array<AWS_Batch_JobDefinition____Environment>;
  Ulimits?: Array<AWS_Batch_JobDefinition____Ulimit>;
  NetworkConfiguration?: AWS_Batch_JobDefinition____NetworkConfiguration;
  InstanceType?: string;
}

export interface IpPermission {
  FromPort: number;
  IpRange: string;
  Protocol: string;
  ToPort: number;
}

export interface RulesSourceList {
  Targets: Array<string>;
  TargetTypes: Array<string>;
  GeneratedRulesType: string;
}

export interface AWS_IoTAnalytics_Pipeline____Lambda {
  BatchSize?: number;
  Next?: string;
  LambdaName?: string;
  Name?: string;
}

export interface AWS_NetworkFirewall_FirewallPolicy____Dimension {
  Value: string;
}

export interface DynamoDBv2 {
  Payload?: Payload;
  TableName: string;
}

export interface OracleSettings {
  SecretsManagerOracleAsmAccessRoleArn?: string;
  SecretsManagerOracleAsmSecretId?: string;
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface OriginGroupMember {
  OriginId: string;
}

export interface Iam {
  Enabled: boolean;
}

export interface AWS_Lambda_Version____ProvisionedConcurrencyConfiguration {
  ProvisionedConcurrentExecutions: number;
}

export interface AWS_ElasticLoadBalancingV2_Listener____AuthenticateCognitoConfig {
  OnUnauthenticatedRequest?: string;
  UserPoolClientId: string;
  UserPoolDomain: string;
  SessionTimeout?: string;
  Scope?: string;
  SessionCookieName?: string;
  UserPoolArn: string;
  AuthenticationRequestExtraParams?: Record<string, string>;
}

export interface AWS_ECS_Service____LoadBalancer {
  ContainerName?: string;
  ContainerPort?: number;
  LoadBalancerName?: string;
  TargetGroupArn?: string;
}

export interface CloudWatchLoggingOptions {
  Enabled?: boolean;
  LogGroupName?: string;
  LogStreamName?: string;
}

export interface ActionThreshold {
  Value: number;
  Type: string;
}

export interface SpotMaintenanceStrategies {
  CapacityRebalance?: SpotCapacityRebalance;
}

export interface CustomSql {
  DataSourceArn: string;
  SqlQuery: string;
  Columns: Array<InputColumn>;
  Name: string;
}

export interface AccelerationSettings {
  Mode: string;
}

export interface AWS_CodeDeploy_DeploymentGroup____TagFilter {
  Key?: string;
  Type?: string;
  Value?: string;
}

export interface AWS_EKS_Nodegroup____LaunchTemplateSpecification {
  Version?: string;
  Id?: string;
  Name?: string;
}

export interface Entitlement {
  Name: string;
  Value?: string;
  MaxCount?: number;
  Overage?: boolean;
  Unit: string;
  AllowCheckIn?: boolean;
}

export interface AWS_Lambda_Function____ImageConfig {
  Command?: Array<string>;
  EntryPoint?: Array<string>;
  WorkingDirectory?: string;
}

export interface SpotFleetTagSpecification {
  ResourceType?: string;
  Tags?: Array<Tag>;
}

export interface AWS_EC2_SpotFleet____PrivateIpAddressSpecification {
  Primary?: boolean;
  PrivateIpAddress: string;
}

export interface AWS_DataBrew_Dataset____Input {
  S3InputDefinition?: AWS_DataBrew_Dataset____S3Location;
  DataCatalogInputDefinition?: AWS_DataBrew_Dataset____DataCatalogInputDefinition;
  DatabaseInputDefinition?: DatabaseInputDefinition;
}

export interface AWS_ElasticLoadBalancingV2_Listener____Action {
  Order?: number;
  TargetGroupArn?: string;
  FixedResponseConfig?: AWS_ElasticLoadBalancingV2_Listener____FixedResponseConfig;
  AuthenticateCognitoConfig?: AWS_ElasticLoadBalancingV2_Listener____AuthenticateCognitoConfig;
  Type: string;
  RedirectConfig?: AWS_ElasticLoadBalancingV2_Listener____RedirectConfig;
  ForwardConfig?: AWS_ElasticLoadBalancingV2_Listener____ForwardConfig;
  AuthenticateOidcConfig?: AWS_ElasticLoadBalancingV2_Listener____AuthenticateOidcConfig;
}

export interface InferenceAccelerator {
  DeviceName?: string;
  DeviceType?: string;
}

export interface AWS_KinesisAnalytics_ApplicationOutput____Output {
  DestinationSchema: AWS_KinesisAnalytics_ApplicationOutput____DestinationSchema;
  LambdaOutput?: AWS_KinesisAnalytics_ApplicationOutput____LambdaOutput;
  KinesisFirehoseOutput?: AWS_KinesisAnalytics_ApplicationOutput____KinesisFirehoseOutput;
  KinesisStreamsOutput?: AWS_KinesisAnalytics_ApplicationOutput____KinesisStreamsOutput;
  Name?: string;
}

export interface InstanceFleetConfig {
  InstanceTypeConfigs?: Array<AWS_EMR_Cluster____InstanceTypeConfig>;
  LaunchSpecifications?: AWS_EMR_Cluster____InstanceFleetProvisioningSpecifications;
  Name?: string;
  TargetOnDemandCapacity?: number;
  TargetSpotCapacity?: number;
}

export interface AWS_QuickSight_Template____DataSetReference {
  DataSetArn: string;
  DataSetPlaceholder: string;
}

export interface ProcessingConfiguration {
  Enabled?: boolean;
  Processors?: Array<Processor>;
}

export interface MySqlParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface JobFlowInstancesConfig {
  AdditionalMasterSecurityGroups?: Array<string>;
  AdditionalSlaveSecurityGroups?: Array<string>;
  CoreInstanceFleet?: InstanceFleetConfig;
  CoreInstanceGroup?: InstanceGroupConfig;
  Ec2KeyName?: string;
  Ec2SubnetId?: string;
  Ec2SubnetIds?: Array<string>;
  EmrManagedMasterSecurityGroup?: string;
  EmrManagedSlaveSecurityGroup?: string;
  HadoopVersion?: string;
  KeepJobFlowAliveWhenNoSteps?: boolean;
  MasterInstanceFleet?: InstanceFleetConfig;
  MasterInstanceGroup?: InstanceGroupConfig;
  Placement?: PlacementType;
  ServiceAccessSecurityGroup?: string;
  TerminationProtected?: boolean;
}

export interface AWS_RDS_DBProxy____TagFormat {
  Key?: string;
  Value?: string;
}

export interface AWS_QuickSight_Analysis____IntegerParameter {
  Values: Array<number>;
  Name: string;
}

export interface AWS_Amplify_App____BasicAuthConfig {
  Username?: string;
  EnableBasicAuth?: boolean;
  Password?: string;
}

export interface AWS_DirectoryService_SimpleAD____VpcSettings {
  SubnetIds: Array<string>;
  VpcId: string;
}

export interface CacheBehavior {
  AllowedMethods?: Array<string>;
  CachePolicyId?: string;
  CachedMethods?: Array<string>;
  Compress?: boolean;
  DefaultTTL?: number;
  FieldLevelEncryptionId?: string;
  ForwardedValues?: ForwardedValues;
  FunctionAssociations?: Array<FunctionAssociation>;
  LambdaFunctionAssociations?: Array<LambdaFunctionAssociation>;
  MaxTTL?: number;
  MinTTL?: number;
  OriginRequestPolicyId?: string;
  PathPattern: string;
  RealtimeLogConfigArn?: string;
  SmoothStreaming?: boolean;
  TargetOriginId: string;
  TrustedKeyGroups?: Array<string>;
  TrustedSigners?: Array<string>;
  ViewerProtocolPolicy: string;
}

export interface BlockerDeclaration {
  Name: string;
  Type: string;
}

export interface AWS_Cassandra_Table____Column {
  ColumnName: string;
  ColumnType: string;
}

export interface StatelessRule {
  RuleDefinition: RuleDefinition;
  Priority: number;
}

export interface AWS_StepFunctions_StateMachine____TagsEntry {
  Key: string;
  Value: string;
}

export interface AWS_MediaConnect_Flow____Source {
  SourceArn?: string;
  Decryption?: AWS_MediaConnect_Flow____Encryption;
  Description?: string;
  EntitlementArn?: string;
  IngestIp?: string;
  IngestPort?: number;
  MaxBitrate?: number;
  MaxLatency?: number;
  Name?: string;
  Protocol?: string;
  StreamId?: string;
  VpcInterfaceName?: string;
  WhitelistCidr?: string;
}

export interface AWS_ApplicationAutoScaling_ScalingPolicy____MetricDimension {
  Name: string;
  Value: string;
}

export interface AWS_ACMPCA_Certificate____OtherName {
  TypeId: string;
  Value: string;
}

export interface MonitoringJobDefinition {
  BaselineConfig?: BaselineConfig;
  Environment?: AWS_SageMaker_MonitoringSchedule____Environment;
  MonitoringAppSpecification: MonitoringAppSpecification;
  MonitoringInputs: Array<MonitoringInput>;
  MonitoringOutputConfig: AWS_SageMaker_MonitoringSchedule____MonitoringOutputConfig;
  MonitoringResources: AWS_SageMaker_MonitoringSchedule____MonitoringResources;
  NetworkConfig?: AWS_SageMaker_MonitoringSchedule____NetworkConfig;
  RoleArn: string;
  StoppingCondition?: AWS_SageMaker_MonitoringSchedule____StoppingCondition;
}

export interface AWS_WAFv2_WebACL____NotStatement {
  Statement: AWS_WAFv2_WebACL____Statement;
}

export interface AWS_AppMesh_VirtualNode____Duration {
  Value: number;
  Unit: string;
}

export interface AWS_CodeCommit_Repository____S3 {
  ObjectVersion?: string;
  Bucket: string;
  Key: string;
}

export interface OnInput {
  Events?: Array<Event>;
  TransitionEvents?: Array<TransitionEvent>;
}

export interface AccessControlAttribute {
  Key: string;
  Value: AccessControlAttributeValue;
}

export interface AWS_Events_Rule____DeadLetterConfig {
  Arn?: string;
}

export interface AWS_SSM_PatchBaseline____RuleGroup {
  PatchRules?: Array<AWS_SSM_PatchBaseline____Rule>;
}

export interface AuthenticationConfiguration {
  RefreshToken: string;
  ClientSecret: string;
  ClientId: string;
}

export interface TaskSchedule {
  ScheduleExpression: string;
}

export interface Behavior {
  Name: string;
  Metric?: string;
  MetricDimension?: AWS_IoT_SecurityProfile____MetricDimension;
  Criteria?: BehaviorCriteria;
  SuppressAlerts?: boolean;
}

export interface AWS_EventSchemas_Registry____TagsEntry {
  Value: string;
  Key: string;
}

export interface AWS_DLM_LifecyclePolicy____Schedule {
  ShareRules?: Array<ShareRule>;
  TagsToAdd?: Array<Tag>;
  CreateRule?: CreateRule;
  VariableTags?: Array<Tag>;
  FastRestoreRule?: FastRestoreRule;
  RetainRule?: RetainRule;
  CrossRegionCopyRules?: Array<CrossRegionCopyRule>;
  Name?: string;
  CopyTags?: boolean;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____ConstraintsResource {
  S3Uri?: string;
}

export interface ActivatedRule {
  Action?: WafAction;
  Priority: number;
  RuleId: string;
}

export interface TransformEncryption {
  MLUserDataEncryption?: MLUserDataEncryption;
  TaskRunSecurityConfigurationName?: string;
}

export interface AWS_DataBrew_Recipe____S3Location {
  Bucket: string;
  Key?: string;
}

export interface TcpRoute {
  Action: TcpRouteAction;
  Timeout?: AWS_AppMesh_Route____TcpTimeout;
}

export interface InforNexusSourceProperties {
  Object: string;
}

export interface LustreConfiguration {
  DriveCacheType?: string;
  ImportPath?: string;
  WeeklyMaintenanceStartTime?: string;
  AutoImportPolicy?: string;
  ImportedFileChunkSize?: number;
  DeploymentType?: string;
  DailyAutomaticBackupStartTime?: string;
  CopyTagsToBackups?: boolean;
  ExportPath?: string;
  PerUnitStorageThroughput?: number;
  AutomaticBackupRetentionDays?: number;
}

export interface AWS_ECS_TaskDefinition____Secret {
  Name: string;
  ValueFrom: string;
}

export interface TrustedSigners {
  Enabled: boolean;
  AwsAccountNumbers?: Array<string>;
}

export interface ApplicationResourceLifecycleConfig {
  ServiceRole?: string;
  VersionLifecycleConfig?: ApplicationVersionLifecycleConfig;
}

export interface AWS_ApplicationInsights_Application____ComponentConfiguration {
  ConfigurationDetails?: ConfigurationDetails;
  SubComponentTypeConfigurations?: Array<SubComponentTypeConfiguration>;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____JSONMappingParameters {
  RecordRowPath: string;
}

export interface SpectrumConfig {
  CenterFrequency?: Frequency;
  Bandwidth?: FrequencyBandwidth;
  Polarization?: string;
}

export interface BufferingHints {
  IntervalInSeconds?: number;
  SizeInMBs?: number;
}

export interface CloudWatchLoggingOption {
  LogStreamARN: string;
}

export interface AWS_IoTAnalytics_Datastore____Column {
  Type: string;
  Name: string;
}

export interface BaselineConfig {
  ConstraintsResource?: AWS_SageMaker_MonitoringSchedule____ConstraintsResource;
  StatisticsResource?: AWS_SageMaker_MonitoringSchedule____StatisticsResource;
}

export interface ExecuteCommandConfiguration {
  KmsKeyId?: string;
  Logging?: string;
  LogConfiguration?: ExecuteCommandLogConfiguration;
}

export interface AWS_Greengrass_CoreDefinitionVersion____Core {
  SyncShadow?: boolean;
  ThingArn: string;
  Id: string;
  CertificateArn: string;
}

export interface OracleParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface S3DestinationProperties {
  BucketName: string;
  BucketPrefix?: string;
  S3OutputFormatConfig?: S3OutputFormatConfig;
}

export interface AWS_RoboMaker_RobotApplication____RobotSoftwareSuite {
  Version: string;
  Name: string;
}

export interface SpotCapacityRebalance {
  ReplacementStrategy?: string;
}

export interface ArtifactStoreMap {
  ArtifactStore: ArtifactStore;
  Region: string;
}

export interface AWS_Synthetics_Canary____Code {
  S3Bucket?: string;
  S3Key?: string;
  S3ObjectVersion?: string;
  Script?: string;
  Handler: string;
}

export interface AWS_IoTEvents_DetectorModel____AssetPropertyVariant {
  BooleanValue?: string;
  DoubleValue?: string;
  IntegerValue?: string;
  StringValue?: string;
}

export interface LegacyCustomOrigin {
  DNSName: string;
  HTTPPort?: number;
  HTTPSPort?: number;
  OriginProtocolPolicy: string;
  OriginSSLProtocols: Array<string>;
}

export interface AWS_SageMaker_Domain____KernelGatewayAppSettings {
  CustomImages?: Array<AWS_SageMaker_Domain____CustomImage>;
  DefaultResourceSpec?: AWS_SageMaker_Domain____ResourceSpec;
}

export interface ConnectionsList {
  Connections?: Array<string>;
}

export interface DefaultCacheBehavior {
  AllowedMethods?: Array<string>;
  CachePolicyId?: string;
  CachedMethods?: Array<string>;
  Compress?: boolean;
  DefaultTTL?: number;
  FieldLevelEncryptionId?: string;
  ForwardedValues?: ForwardedValues;
  FunctionAssociations?: Array<FunctionAssociation>;
  LambdaFunctionAssociations?: Array<LambdaFunctionAssociation>;
  MaxTTL?: number;
  MinTTL?: number;
  OriginRequestPolicyId?: string;
  RealtimeLogConfigArn?: string;
  SmoothStreaming?: boolean;
  TargetOriginId: string;
  TrustedKeyGroups?: Array<string>;
  TrustedSigners?: Array<string>;
  ViewerProtocolPolicy: string;
}

export interface Variable {
  DatasetContentVersionValue?: DatasetContentVersionValue;
  DoubleValue?: number;
  OutputFileUriValue?: OutputFileUriValue;
  VariableName: string;
  StringValue?: string;
}

export interface ArtifactDetails {
  MaximumCount: number;
  MinimumCount: number;
}

export interface AWS_Lambda_EventSourceMapping____OnFailure {
  Destination?: string;
}

export interface GitHubLocation {
  CommitId: string;
  Repository: string;
}

export interface AWS_Greengrass_FunctionDefinitionVersion____RunAs {
  Uid?: number;
  Gid?: number;
}

export interface AWS_CloudFormation_StackSet____Parameter {
  ParameterKey: string;
  ParameterValue: string;
}

export interface VirtualGatewayListener {
  ConnectionPool?: VirtualGatewayConnectionPool;
  HealthCheck?: VirtualGatewayHealthCheckPolicy;
  TLS?: VirtualGatewayListenerTls;
  PortMapping: VirtualGatewayPortMapping;
}

export interface FilterConfiguration {
  AllowedLocations?: Array<string>;
}

export interface AWS_EMR_Step____KeyValue {
  Key?: string;
  Value?: string;
}

export interface CustomizedScalingMetricSpecification {
  MetricName: string;
  Statistic: string;
  Dimensions?: Array<AWS_AutoScalingPlans_ScalingPlan____MetricDimension>;
  Unit?: string;
  Namespace: string;
}

export interface AWS_EC2_NetworkInsightsAnalysis____PortRange {
  From?: number;
  To?: number;
}

export interface AWS_SageMaker_DataQualityJobDefinition____MonitoringResources {
  ClusterConfig: AWS_SageMaker_DataQualityJobDefinition____ClusterConfig;
}

export interface HttpRetryPolicy {
  MaxRetries: number;
  PerRetryTimeout: AWS_AppMesh_Route____Duration;
  HttpRetryEvents?: Array<string>;
  TcpRetryEvents?: Array<string>;
}

export interface RenderingEngine {
  Version: string;
  Name: string;
}

export interface AWS_OpsWorks_App____EnvironmentVariable {
  Key: string;
  Secure?: boolean;
  Value: string;
}

export interface Sasl {
  Iam?: Iam;
  Scram?: Scram;
}

export interface AWS_ApiGateway_Stage____CanarySetting {
  DeploymentId?: string;
  PercentTraffic?: number;
  StageVariableOverrides?: Record<string, string>;
  UseStageCache?: boolean;
}

export interface CloudWatchEncryption {
  KmsKeyArn?: string;
  CloudWatchEncryptionMode?: string;
}

export interface SourceAccessConfiguration {
  Type?: string;
  URI?: string;
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule____FixedResponseConfig {
  ContentType?: string;
  StatusCode: string;
  MessageBody?: string;
}

export interface ConfigurationParameter {
  Name?: string;
  Values?: Array<string>;
}

export interface DashboardPublishOptions {
  SheetControlsOption?: SheetControlsOption;
  ExportToCSVOption?: ExportToCSVOption;
  AdHocFilteringOption?: AdHocFilteringOption;
}

export interface AWS_S3_Bucket____NotificationConfiguration {
  LambdaConfigurations?: Array<LambdaConfiguration>;
  QueueConfigurations?: Array<QueueConfiguration>;
  TopicConfigurations?: Array<TopicConfiguration>;
}

export interface AWS_EMR_InstanceFleetConfig____EbsConfiguration {
  EbsBlockDeviceConfigs?: Array<AWS_EMR_InstanceFleetConfig____EbsBlockDeviceConfig>;
  EbsOptimized?: boolean;
}

export interface FederationParameters {
  SamlMetadataURL?: string;
  FederationProviderName?: string;
  SamlMetadataDocument?: string;
  ApplicationCallBackURL?: string;
  FederationURN?: string;
  AttributeMap?: any;
}

export interface AWS_EC2_SpotFleet____EbsBlockDevice {
  DeleteOnTermination?: boolean;
  Encrypted?: boolean;
  Iops?: number;
  SnapshotId?: string;
  VolumeSize?: number;
  VolumeType?: string;
}

export interface Range {
  EndTime: string;
  StartTime: string;
}

export interface ThemeConfiguration {
  DataColorPalette?: DataColorPalette;
  UIColorPalette?: UIColorPalette;
  Sheet?: SheetStyle;
  Typography?: Typography;
}

export interface SourceAuth {
  Type: string;
  Resource?: string;
}

export interface AWS_Glue_Crawler____Targets {
  S3Targets?: Array<S3Target>;
  CatalogTargets?: Array<CatalogTarget>;
  JdbcTargets?: Array<JdbcTarget>;
  DynamoDBTargets?: Array<DynamoDBTarget>;
}

export interface AWS_Events_Rule____NetworkConfiguration {
  AwsVpcConfiguration?: AWS_Events_Rule____AwsVpcConfiguration;
}

export interface S3Destination {
  KMSKeyArn?: string;
  BucketPrefix?: string;
  BucketName: string;
  BucketRegion: string;
  SyncFormat: string;
}

export interface TlsValidationContextTrust {
  SDS?: TlsValidationContextSdsTrust;
  ACM?: TlsValidationContextAcmTrust;
  File?: TlsValidationContextFileTrust;
}

export interface AWS_WAFv2_RuleGroup____TextTransformation {
  Priority: number;
  Type: string;
}

export interface RecordSet {
  AliasTarget?: AWS_Route53_RecordSetGroup____AliasTarget;
  Comment?: string;
  Failover?: string;
  GeoLocation?: AWS_Route53_RecordSetGroup____GeoLocation;
  HealthCheckId?: string;
  HostedZoneId?: string;
  HostedZoneName?: string;
  MultiValueAnswer?: boolean;
  Name: string;
  Region?: string;
  ResourceRecords?: Array<string>;
  SetIdentifier?: string;
  TTL?: string;
  Type: string;
  Weight?: number;
}

export interface Restrictions {
  GeoRestriction: GeoRestriction;
}

export interface ResponseParameter {
  Destination: string;
  Source: string;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____SageMakerMachineLearningModelResourceData {
  OwnerSetting?: AWS_Greengrass_ResourceDefinitionVersion____ResourceDownloadOwnerSetting;
  DestinationPath: string;
  SageMakerJobArn: string;
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule____Action {
  Order?: number;
  TargetGroupArn?: string;
  FixedResponseConfig?: AWS_ElasticLoadBalancingV2_ListenerRule____FixedResponseConfig;
  AuthenticateCognitoConfig?: AWS_ElasticLoadBalancingV2_ListenerRule____AuthenticateCognitoConfig;
  Type: string;
  RedirectConfig?: AWS_ElasticLoadBalancingV2_ListenerRule____RedirectConfig;
  ForwardConfig?: AWS_ElasticLoadBalancingV2_ListenerRule____ForwardConfig;
  AuthenticateOidcConfig?: AWS_ElasticLoadBalancingV2_ListenerRule____AuthenticateOidcConfig;
}

export interface LoadBalancersConfig {
  ClassicLoadBalancersConfig?: ClassicLoadBalancersConfig;
  TargetGroupsConfig?: TargetGroupsConfig;
}

export interface ProcessorParameter {
  ParameterName: string;
  ParameterValue: string;
}

export interface SnowflakeConnectorProfileProperties {
  Warehouse: string;
  Stage: string;
  BucketName: string;
  BucketPrefix?: string;
  PrivateLinkServiceName?: string;
  AccountName?: string;
  Region?: string;
}

export interface AWS_ECS_TaskSet____AwsVpcConfiguration {
  AssignPublicIp?: string;
  SecurityGroups?: Array<string>;
  Subnets: Array<string>;
}

export interface ParquetConfiguration {
  SchemaDefinition?: SchemaDefinition;
}

export interface AWS_QuickSight_Dashboard____DecimalParameter {
  Values: Array<number>;
  Name: string;
}

export interface ELBInfo {
  Name?: string;
}

export interface LifecycleResourceType {
  MoveToColdStorageAfterDays?: number;
  DeleteAfterDays?: number;
}

export interface RunCommandTarget {
  Key: string;
  Values: Array<string>;
}

export interface StageDescription {
  AccessLogSetting?: AWS_ApiGateway_Deployment____AccessLogSetting;
  CacheClusterEnabled?: boolean;
  CacheClusterSize?: string;
  CacheDataEncrypted?: boolean;
  CacheTtlInSeconds?: number;
  CachingEnabled?: boolean;
  CanarySetting?: AWS_ApiGateway_Deployment____CanarySetting;
  ClientCertificateId?: string;
  DataTraceEnabled?: boolean;
  Description?: string;
  DocumentationVersion?: string;
  LoggingLevel?: string;
  MethodSettings?: Array<AWS_ApiGateway_Deployment____MethodSetting>;
  MetricsEnabled?: boolean;
  Tags?: Array<Tag>;
  ThrottlingBurstLimit?: number;
  ThrottlingRateLimit?: number;
  TracingEnabled?: boolean;
  Variables?: Record<string, string>;
}

export interface ServerProcess {
  ConcurrentExecutions: number;
  LaunchPath: string;
  Parameters?: string;
}

export interface AuthFormat {
  AuthScheme?: string;
  Description?: string;
  IAMAuth?: string;
  SecretArn?: string;
  UserName?: string;
}

export interface EnvironmentFile {
  Value?: string;
  Type?: string;
}

export interface FleetLaunchTemplateSpecification {
  LaunchTemplateId?: string;
  LaunchTemplateName?: string;
  Version: string;
}

export interface RedirectAllRequestsTo {
  HostName: string;
  Protocol?: string;
}

export interface AWS_WAF_XssMatchSet____XssMatchTuple {
  FieldToMatch: AWS_WAF_XssMatchSet____FieldToMatch;
  TextTransformation: string;
}

export interface VirtualGatewayPortMapping {
  Port: number;
  Protocol: string;
}

export interface S3KeyFilter {
  Rules: Array<AWS_S3_Bucket____FilterRule>;
}

export interface AWS_SageMaker_DataQualityJobDefinition____MonitoringOutput {
  S3Output: AWS_SageMaker_DataQualityJobDefinition____S3Output;
}

export interface AWS_WAFv2_RuleGroup____ByteMatchStatement {
  SearchString?: string;
  SearchStringBase64?: string;
  FieldToMatch: AWS_WAFv2_RuleGroup____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_RuleGroup____TextTransformation>;
  PositionalConstraint: string;
}

export interface ConfigurationInfo {
  Revision: number;
  Arn: string;
}

export interface LBCookieStickinessPolicy {
  CookieExpirationPeriod?: string;
  PolicyName?: string;
}

export interface AWS_EC2_Instance____Volume {
  Device: string;
  VolumeId: string;
}

export interface AWS_SageMaker_DataQualityJobDefinition____MonitoringOutputConfig {
  KmsKeyId?: string;
  MonitoringOutputs: Array<AWS_SageMaker_DataQualityJobDefinition____MonitoringOutput>;
}

export interface AWS_EC2_NetworkAclEntry____PortRange {
  From?: number;
  To?: number;
}

export interface Origin {
  ConnectionAttempts?: number;
  ConnectionTimeout?: number;
  CustomOriginConfig?: CustomOriginConfig;
  DomainName: string;
  Id: string;
  OriginCustomHeaders?: Array<OriginCustomHeader>;
  OriginPath?: string;
  S3OriginConfig?: S3OriginConfig;
}

export interface GitConfig {
  SecretArn?: string;
  Branch?: string;
  RepositoryUrl: string;
}

export interface InputTransformer {
  InputPathsMap?: Record<string, string>;
  InputTemplate: string;
}

export interface FirehoseAction {
  DeliveryStreamName: string;
  RoleArn: string;
  Separator?: string;
  BatchMode?: boolean;
}

export interface InventoryConfiguration {
  Destination: AWS_S3_Bucket____Destination;
  Enabled: boolean;
  Id: string;
  IncludedObjectVersions: string;
  OptionalFields?: Array<string>;
  Prefix?: string;
  ScheduleFrequency: string;
}

export interface WorkspaceProperties {
  ComputeTypeName?: string;
  RootVolumeSizeGib?: number;
  RunningMode?: string;
  RunningModeAutoStopTimeoutInMinutes?: number;
  UserVolumeSizeGib?: number;
}

export interface VolumeFrom {
  ReadOnly?: boolean;
  SourceContainer?: string;
}

export interface AWS_Greengrass_FunctionDefinition____Environment {
  Variables?: any;
  Execution?: AWS_Greengrass_FunctionDefinition____Execution;
  ResourceAccessPolicies?: Array<AWS_Greengrass_FunctionDefinition____ResourceAccessPolicy>;
  AccessSysfs?: boolean;
}

export type AWS_CloudWatch_InsightRule____Tags = Tag[];

export interface SourceConnectorProperties {
  Amplitude?: AmplitudeSourceProperties;
  Datadog?: DatadogSourceProperties;
  Dynatrace?: DynatraceSourceProperties;
  GoogleAnalytics?: GoogleAnalyticsSourceProperties;
  InforNexus?: InforNexusSourceProperties;
  Marketo?: MarketoSourceProperties;
  S3?: S3SourceProperties;
  Salesforce?: SalesforceSourceProperties;
  ServiceNow?: ServiceNowSourceProperties;
  Singular?: SingularSourceProperties;
  Slack?: SlackSourceProperties;
  Trendmicro?: TrendmicroSourceProperties;
  Veeva?: VeevaSourceProperties;
  Zendesk?: ZendeskSourceProperties;
}

export interface DeltaTime {
  TimeExpression: string;
  OffsetSeconds: number;
}

export interface AWS_GroundStation_DataflowEndpointGroup____EndpointDetails {
  SecurityDetails?: SecurityDetails;
  Endpoint?: DataflowEndpoint;
}

export interface Outcome {
  Arn?: string;
  Inline?: boolean;
  Name?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface AWS_SageMaker_MonitoringSchedule____MonitoringOutput {
  S3Output: AWS_SageMaker_MonitoringSchedule____S3Output;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____StoppingCondition {
  MaxRuntimeInSeconds: number;
}

export interface BrokerNodeGroupInfo {
  SecurityGroups?: Array<string>;
  ClientSubnets: Array<string>;
  StorageInfo?: StorageInfo;
  BrokerAZDistribution?: string;
  InstanceType: string;
}

export interface Endpoints {
  KafkaBootstrapServers?: Array<string>;
}

export interface AWS_WAFv2_RuleGroup____RegexPatternSetReferenceStatement {
  Arn: string;
  FieldToMatch: AWS_WAFv2_RuleGroup____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_RuleGroup____TextTransformation>;
}

export interface AWS_Cognito_UserPoolClient____AnalyticsConfiguration {
  ApplicationArn?: string;
  UserDataShared?: boolean;
  ExternalId?: string;
  ApplicationId?: string;
  RoleArn?: string;
}

export interface AWS_S3_Bucket____ReplicationConfiguration {
  Role: string;
  Rules: Array<AWS_S3_Bucket____ReplicationRule>;
}

export interface CFNS3LogsConfiguration {
  Enable?: boolean;
}

export interface DataQualityAppSpecification {
  ContainerArguments?: Array<string>;
  ContainerEntrypoint?: Array<string>;
  ImageUri: string;
  PostAnalyticsProcessorSourceUri?: string;
  RecordPreprocessorSourceUri?: string;
  Environment?: AWS_SageMaker_DataQualityJobDefinition____Environment;
}

export interface HomeDirectoryMapEntry {
  Entry: string;
  Target: string;
}

export interface AWS_KinesisAnalytics_Application____InputSchema {
  RecordEncoding?: string;
  RecordColumns: Array<AWS_KinesisAnalytics_Application____RecordColumn>;
  RecordFormat: AWS_KinesisAnalytics_Application____RecordFormat;
}

export interface AwsIamConfig {
  SigningRegion?: string;
  SigningServiceName?: string;
}

export interface AWS_KinesisAnalyticsV2_Application____KinesisStreamsInput {
  ResourceARN: string;
}

export interface Scram {
  Enabled: boolean;
}

export interface HostEntry {
  Hostname?: string;
  IpAddress?: string;
}

export interface ClusteringKeyColumn {
  Column: AWS_Cassandra_Table____Column;
  OrderBy?: string;
}

export interface EmailConfiguration {
  ReplyToEmailAddress?: string;
  ConfigurationSet?: string;
  EmailSendingAccount?: string;
  SourceArn?: string;
  From?: string;
}

export interface SelfManagedActiveDirectoryConfiguration {
  FileSystemAdministratorsGroup?: string;
  UserName?: string;
  DomainName?: string;
  OrganizationalUnitDistinguishedName?: string;
  DnsIps?: Array<string>;
  Password?: string;
}

export interface AWS_EMR_InstanceGroupConfig____ScalingAction {
  Market?: string;
  SimpleScalingPolicyConfiguration: AWS_EMR_InstanceGroupConfig____SimpleScalingPolicyConfiguration;
}

export interface Listeners {
  InstancePort: string;
  InstanceProtocol?: string;
  LoadBalancerPort: string;
  PolicyNames?: Array<string>;
  Protocol: string;
  SSLCertificateId?: string;
}

export interface AWS_EMR_InstanceGroupConfig____ScalingTrigger {
  CloudWatchAlarmDefinition: AWS_EMR_InstanceGroupConfig____CloudWatchAlarmDefinition;
}

export interface AWS_CloudWatch_AnomalyDetector____Dimension {
  Value: string;
  Name: string;
}

export interface MaintenanceWindow {
  DayOfWeek: string;
  TimeOfDay: string;
  TimeZone: string;
}

export interface FirewallPolicy {
  StatelessDefaultActions: Array<string>;
  StatelessFragmentDefaultActions: Array<string>;
  StatelessCustomActions?: Array<AWS_NetworkFirewall_FirewallPolicy____CustomAction>;
  StatelessRuleGroupReferences?: Array<StatelessRuleGroupReference>;
  StatefulRuleGroupReferences?: Array<StatefulRuleGroupReference>;
}

export interface TargetGroup {
  Arn: string;
}

export interface OnDemandOptionsRequest {
  SingleAvailabilityZone?: boolean;
  AllocationStrategy?: string;
  SingleInstanceType?: boolean;
  MinTargetCapacity?: number;
  MaxTotalPrice?: string;
  CapacityReservationOptions?: CapacityReservationOptionsRequest;
}

export interface TaskDefinitionPlacementConstraint {
  Type: string;
  Expression?: string;
}

export interface FilterValue {
  ValueReference: string;
  Value: string;
}

export type AWS_SageMaker_ModelBiasJobDefinition____Environment = undefined;

export interface HttpUrlDestinationSummary {
  ConfirmationUrl?: string;
}

export interface JdbcTarget {
  ConnectionName?: string;
  Path?: string;
  Exclusions?: Array<string>;
}

export interface SetVariable {
  Value: string;
  VariableName: string;
}

export interface ConnectionLogOptions {
  CloudwatchLogStream?: string;
  Enabled: boolean;
  CloudwatchLogGroup?: string;
}

export interface Distribution {
  Region: string;
  AmiDistributionConfiguration?: any;
  ContainerDistributionConfiguration?: any;
  LicenseConfigurationArns?: Array<string>;
  LaunchTemplateConfigurations?: Array<LaunchTemplateConfiguration>;
}

export interface SalesforceConnectorProfileProperties {
  InstanceUrl?: string;
  isSandboxEnvironment?: boolean;
}

export interface FunctionDefinitionVersion {
  DefaultConfig?: AWS_Greengrass_FunctionDefinition____DefaultConfig;
  Functions: Array<AWS_Greengrass_FunctionDefinition____Function>;
}

export interface DeliveryStreamEncryptionConfigurationInput {
  KeyARN?: string;
  KeyType: string;
}

export interface AWS_WAFv2_RuleGroup____OrStatement {
  Statements: Array<AWS_WAFv2_RuleGroup____Statement>;
}

export interface AWS_EMR_InstanceFleetConfig____OnDemandProvisioningSpecification {
  AllocationStrategy: string;
}

export interface VariantProperty {
  VariantPropertyType?: string;
}

export interface Selector {
  Namespace: string;
  Labels?: Array<AWS_EKS_FargateProfile____Label>;
}

export interface CaptureContentTypeHeader {
  JsonContentTypes?: Array<string>;
  CsvContentTypes?: Array<string>;
}

export interface AWS_RDS_DBProxyEndpoint____TagFormat {
  Key?: string;
  Value?: string;
}

export interface DeploymentConfiguration {
  DeploymentCircuitBreaker?: DeploymentCircuitBreaker;
  MaximumPercent?: number;
  MinimumHealthyPercent?: number;
}

export interface AWS_IoT_TopicRule____AssetPropertyTimestamp {
  TimeInSeconds: string;
  OffsetInNanos?: string;
}

export interface MountPoints {
  ReadOnly?: boolean;
  SourceVolume?: string;
  ContainerPath?: string;
}

export interface AWS_FraudDetector_EventType____EntityType {
  Arn?: string;
  Inline?: boolean;
  Name?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface DatastoreStorage {
  CustomerManagedS3?: AWS_IoTAnalytics_Datastore____CustomerManagedS3;
  ServiceManagedS3?: AWS_IoTAnalytics_Datastore____ServiceManagedS3;
}

export interface OverrideAction {
  Count?: any;
  None?: any;
}

export interface AWS_ApiGateway_Deployment____CanarySetting {
  PercentTraffic?: number;
  StageVariableOverrides?: Record<string, string>;
  UseStageCache?: boolean;
}

export interface AWS_CodeDeploy_DeploymentGroup____Alarm {
  Name?: string;
}

export interface SchemaAttribute {
  DeveloperOnlyAttribute?: boolean;
  Mutable?: boolean;
  AttributeDataType?: string;
  StringAttributeConstraints?: StringAttributeConstraints;
  Required?: boolean;
  NumberAttributeConstraints?: NumberAttributeConstraints;
  Name?: string;
}

export interface AWS_MWAA_Environment____NetworkConfiguration {
  SubnetIds?: Array<string>;
  SecurityGroupIds?: Array<string>;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____VpcConfig {
  SecurityGroupIds: Array<string>;
  Subnets: Array<string>;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____ResourceDownloadOwnerSetting {
  GroupOwner: string;
  GroupPermission: string;
}

export interface AWS_SageMaker_UserProfile____CustomImage {
  AppImageConfigName: string;
  ImageName: string;
  ImageVersionNumber?: number;
}

export interface AWS_IoT_TopicRule____AssetPropertyValue {
  Value: AWS_IoT_TopicRule____AssetPropertyVariant;
  Timestamp: AWS_IoT_TopicRule____AssetPropertyTimestamp;
  Quality?: string;
}

export interface AWS_QuickSight_Analysis____Parameters {
  StringParameters?: Array<AWS_QuickSight_Analysis____StringParameter>;
  DecimalParameters?: Array<AWS_QuickSight_Analysis____DecimalParameter>;
  IntegerParameters?: Array<AWS_QuickSight_Analysis____IntegerParameter>;
  DateTimeParameters?: Array<AWS_QuickSight_Analysis____DateTimeParameter>;
}

export interface IamInstanceProfile {
  Arn?: string;
  Name?: string;
}

export interface AWS_ImageBuilder_ImagePipeline____Schedule {
  ScheduleExpression?: string;
  PipelineExecutionStartCondition?: string;
}

export interface NumberAttributeConstraints {
  MinValue?: string;
  MaxValue?: string;
}

export interface CheckpointConfiguration {
  ConfigurationType: string;
  CheckpointInterval?: number;
  MinPauseBetweenCheckpoints?: number;
  CheckpointingEnabled?: boolean;
}

export interface ModuleLoggingConfiguration {
  Enabled?: boolean;
  LogLevel?: string;
  CloudWatchLogGroupArn?: string;
}

export interface CustomSMSSender {
  LambdaArn?: string;
  LambdaVersion?: string;
}

export interface AWS_Glue_Table____SchemaId {
  RegistryName?: string;
  SchemaName?: string;
  SchemaArn?: string;
}

export interface AWS_AmazonMQ_Broker____TagsEntry {
  Value: string;
  Key: string;
}

export interface AWS_OpsWorks_Instance____EbsBlockDevice {
  DeleteOnTermination?: boolean;
  Iops?: number;
  SnapshotId?: string;
  VolumeSize?: number;
  VolumeType?: string;
}

export interface AWS_ElastiCache_CacheCluster____LogDeliveryConfigurationRequest {
  DestinationDetails?: AWS_ElastiCache_CacheCluster____DestinationDetails;
  DestinationType?: string;
  LogFormat?: string;
  LogType?: string;
}

export interface ResourceCreationLimitPolicy {
  NewGameSessionsPerCreator?: number;
  PolicyPeriodInMinutes?: number;
}

export interface AWS_AutoScaling_ScalingPolicy____StepAdjustment {
  MetricIntervalLowerBound?: number;
  MetricIntervalUpperBound?: number;
  ScalingAdjustment: number;
}

export interface MemberFrameworkConfiguration {
  MemberFabricConfiguration?: MemberFabricConfiguration;
}

export interface CustomComponent {
  ComponentName: string;
  ResourceList: Array<string>;
}

export interface AWS_SageMaker_UserProfile____SharingSettings {
  NotebookOutputOption?: string;
  S3KmsKeyId?: string;
  S3OutputPath?: string;
}

export interface HttpGatewayRouteAction {
  Target: GatewayRouteTarget;
}

export interface ElasticsearchAction {
  Type: string;
  Index: string;
  Id: string;
  Endpoint: string;
  RoleArn: string;
}

export interface ApplicationVersionLifecycleConfig {
  MaxAgeRule?: MaxAgeRule;
  MaxCountRule?: MaxCountRule;
}

export interface Validators {
  Type?: string;
  Content?: string;
}

export interface DefinitionParameter {
  Key: string;
  Value: string;
}

export interface ListenerTlsAcmCertificate {
  CertificateArn: string;
}

export interface Trigger {
  Schedule?: AWS_IoTAnalytics_Dataset____Schedule;
  TriggeringDataset?: TriggeringDataset;
}

export interface Matcher {
  GrpcCode?: string;
  HttpCode?: string;
}

export interface DeviceTemplate {
  DeviceType?: string;
  CallbackOverrides?: any;
}

export interface AWS_Greengrass_FunctionDefinition____RunAs {
  Uid?: number;
  Gid?: number;
}

export interface VirtualGatewayBackendDefaults {
  ClientPolicy?: VirtualGatewayClientPolicy;
}

export interface ScheduleConfig {
  ScheduleExpression: string;
}

export interface AWS_AutoScalingPlans_ScalingPlan____TagFilter {
  Values?: Array<string>;
  Key: string;
}

export interface AmazonElasticsearchParameters {
  Domain: string;
}

export interface AWS_StepFunctions_StateMachine____LoggingConfiguration {
  Level?: string;
  IncludeExecutionData?: boolean;
  Destinations?: Array<LogDestination>;
}

export type AWS_SageMaker_ModelQualityJobDefinition____Environment = undefined;

export interface ConnectorProfileConfig {
  ConnectorProfileProperties?: ConnectorProfileProperties;
  ConnectorProfileCredentials: ConnectorProfileCredentials;
}

export interface ProjectFileSystemLocation {
  MountPoint: string;
  Type: string;
  Identifier: string;
  MountOptions?: string;
  Location: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____ReferenceDataSource {
  ReferenceSchema: AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____ReferenceSchema;
  TableName?: string;
  S3ReferenceDataSource?: AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____S3ReferenceDataSource;
}

export interface AccessMethod {
  CustomObjectIdentifier?: string;
  AccessMethodType?: string;
}

export interface AWS_Greengrass_DeviceDefinitionVersion____Device {
  SyncShadow?: boolean;
  ThingArn: string;
  Id: string;
  CertificateArn: string;
}

export interface AWS_NetworkFirewall_RuleGroup____PortRange {
  FromPort: number;
  ToPort: number;
}

export interface AWS_ECS_TaskDefinition____Volume {
  DockerVolumeConfiguration?: DockerVolumeConfiguration;
  EFSVolumeConfiguration?: EFSVolumeConfiguration;
  Host?: HostVolumeProperties;
  Name?: string;
}

export interface AWS_ImageBuilder_Image____ImageTestsConfiguration {
  ImageTestsEnabled?: boolean;
  TimeoutMinutes?: number;
}

export type TagMap = undefined;

export interface IPSet {
  Definition?: Array<string>;
}

export interface Payload {
  ContentExpression: string;
  Type: string;
}

export interface HealthCheckCustomConfig {
  FailureThreshold?: number;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____MonitoringOutputConfig {
  KmsKeyId?: string;
  MonitoringOutputs: Array<AWS_SageMaker_ModelBiasJobDefinition____MonitoringOutput>;
}

export interface S3OutputLocation {
  OutputS3Region?: string;
  OutputS3BucketName?: string;
  OutputS3KeyPrefix?: string;
}

export interface AuthorizerConfig {
  AllowAuthorizerOverride?: boolean;
  DefaultAuthorizerName?: string;
}

export interface AWS_WAFRegional_WebACL____Action {
  Type: string;
}

export interface TrendmicroSourceProperties {
  Object: string;
}

export interface AWS_KinesisAnalyticsV2_Application____InputLambdaProcessor {
  ResourceARN: string;
}

export interface AWS_EC2_LaunchTemplate____LicenseSpecification {
  LicenseConfigurationArn?: string;
}

export interface CorsConfiguration {
  CorsRules: Array<CorsRule>;
}

export interface AWS_S3_Bucket____ReplicationDestination {
  AccessControlTranslation?: AccessControlTranslation;
  Account?: string;
  Bucket: string;
  EncryptionConfiguration?: AWS_S3_Bucket____EncryptionConfiguration;
  Metrics?: Metrics;
  ReplicationTime?: ReplicationTime;
  StorageClass?: string;
}

export interface Egress {
  CidrIp?: string;
  CidrIpv6?: string;
  Description?: string;
  DestinationPrefixListId?: string;
  DestinationSecurityGroupId?: string;
  FromPort?: number;
  IpProtocol: string;
  ToPort?: number;
}

export interface VirtualGatewayClientPolicyTls {
  Validation: VirtualGatewayTlsValidationContext;
  Enforce?: boolean;
  Ports?: Array<number>;
  Certificate?: VirtualGatewayClientTlsCertificate;
}

export interface AWS_IoTAnalytics_Pipeline____Channel {
  ChannelName?: string;
  Next?: string;
  Name?: string;
}

export interface CreationInfo {
  OwnerUid: string;
  OwnerGid: string;
  Permissions: string;
}

export interface Validity {
  Value: number;
  Type: string;
}

export interface KinesisAction {
  PartitionKey?: string;
  StreamName: string;
  RoleArn: string;
}

export interface MeshSpec {
  EgressFilter?: EgressFilter;
}

export interface AWS_RoboMaker_RobotApplication____SourceConfig {
  S3Bucket: string;
  Architecture: string;
  S3Key: string;
}

export interface LifecycleEventConfiguration {
  ShutdownEventConfiguration?: ShutdownEventConfiguration;
}

export interface MonitoringScheduleConfig {
  MonitoringJobDefinition?: MonitoringJobDefinition;
  MonitoringJobDefinitionName?: string;
  MonitoringType?: string;
  ScheduleConfig?: ScheduleConfig;
}

export interface CostTypes {
  IncludeSupport?: boolean;
  IncludeOtherSubscription?: boolean;
  IncludeTax?: boolean;
  IncludeSubscription?: boolean;
  UseBlended?: boolean;
  IncludeUpfront?: boolean;
  IncludeDiscount?: boolean;
  IncludeCredit?: boolean;
  IncludeRecurring?: boolean;
  UseAmortized?: boolean;
  IncludeRefund?: boolean;
}

export interface VirtualGatewayAccessLog {
  File?: VirtualGatewayFileAccessLog;
}

export interface PublicKeyConfig {
  CallerReference: string;
  Comment?: string;
  EncodedKey: string;
  Name: string;
}

export interface AWS_SageMaker_DataQualityJobDefinition____ClusterConfig {
  InstanceCount: number;
  InstanceType: string;
  VolumeKmsKeyId?: string;
  VolumeSizeInGB: number;
}

export interface AWS_IoT_TopicRule____Action {
  S3?: S3Action;
  CloudwatchAlarm?: CloudwatchAlarmAction;
  CloudwatchLogs?: CloudwatchLogsAction;
  IotEvents?: IotEventsAction;
  Firehose?: FirehoseAction;
  Republish?: RepublishAction;
  StepFunctions?: StepFunctionsAction;
  DynamoDB?: DynamoDBAction;
  Http?: HttpAction;
  DynamoDBv2?: DynamoDBv2Action;
  CloudwatchMetric?: CloudwatchMetricAction;
  IotSiteWise?: IotSiteWiseAction;
  Elasticsearch?: ElasticsearchAction;
  Sqs?: SqsAction;
  Kinesis?: KinesisAction;
  IotAnalytics?: IotAnalyticsAction;
  Sns?: SnsAction;
  Lambda?: LambdaAction;
  Timestream?: TimestreamAction;
  Kafka?: KafkaAction;
}

export interface AWS_NetworkFirewall_LoggingConfiguration____LoggingConfiguration {
  LogDestinationConfigs: Array<LogDestinationConfig>;
}

export interface JWTConfiguration {
  Issuer?: string;
  Audience?: Array<string>;
}

export interface AWS_IoTAnalytics_Pipeline____Filter {
  Filter?: string;
  Next?: string;
  Name?: string;
}

export interface RegionalConfiguration {
  ReplicationGroupId?: string;
  ReplicationGroupRegion?: string;
  ReshardingConfigurations?: Array<ReshardingConfiguration>;
}

export interface IotEventsDestinationConfiguration {
  InputName: string;
  RoleArn: string;
}

export interface AmplitudeConnectorProfileCredentials {
  ApiKey: string;
  SecretKey: string;
}

export interface ManagedScaling {
  MinimumScalingStepSize?: number;
  MaximumScalingStepSize?: number;
  Status?: string;
  TargetCapacity?: number;
}

export interface NoncurrentVersionTransition {
  StorageClass: string;
  TransitionInDays: number;
}

export interface AWS_QuickSight_Analysis____StringParameter {
  Values: Array<string>;
  Name: string;
}

export interface NotifyEmailType {
  TextBody?: string;
  HtmlBody?: string;
  Subject: string;
}

export interface AWS_LakeFormation_Permissions____DataLakePrincipal {
  DataLakePrincipalIdentifier?: string;
}

export interface AWS_WAFv2_RuleGroup____Rule {
  Name: string;
  Priority: number;
  Statement: AWS_WAFv2_RuleGroup____Statement;
  Action?: AWS_WAFv2_RuleGroup____RuleAction;
  RuleLabels?: Array<AWS_WAFv2_RuleGroup____Label>;
  VisibilityConfig: AWS_WAFv2_RuleGroup____VisibilityConfig;
}

export interface AWS_QuickSight_DataSet____ResourcePermission {
  Actions: Array<string>;
  Principal: string;
}

export interface AllowedPublishers {
  SigningProfileVersionArns: Array<string>;
}

export interface ConnectorOAuthRequest {
  AuthCode?: string;
  RedirectUri?: string;
}

export interface AWS_WAFv2_RuleGroup____JsonBody {
  MatchPattern: AWS_WAFv2_RuleGroup____JsonMatchPattern;
  MatchScope: string;
  InvalidFallbackBehavior?: string;
}

export interface AWS_AppMesh_Route____GrpcTimeout {
  PerRequest?: AWS_AppMesh_Route____Duration;
  Idle?: AWS_AppMesh_Route____Duration;
}

export interface FieldFolder {
  Description?: string;
  Columns?: Array<string>;
}

export interface ValidityDateFormat {
  Begin: string;
  End: string;
}

export interface VirtualNodeHttp2ConnectionPool {
  MaxRequests: number;
}

export interface DatadogConnectorProfileCredentials {
  ApiKey: string;
  ApplicationKey: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____MappingParameters {
  JSONMappingParameters?: AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____JSONMappingParameters;
  CSVMappingParameters?: AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____CSVMappingParameters;
}

export interface SnapshotOptions {
  AutomatedSnapshotStartHour?: number;
}

export interface SnowflakeDestinationProperties {
  Object: string;
  IntermediateBucketName: string;
  BucketPrefix?: string;
  ErrorHandlingConfig?: ErrorHandlingConfig;
}

export interface TableResource {
  DatabaseName?: string;
  CatalogId?: string;
  TableWildcard?: TableWildcard;
  Name?: string;
}

export interface AWS_SageMaker_DataQualityJobDefinition____VpcConfig {
  SecurityGroupIds: Array<string>;
  Subnets: Array<string>;
}

export interface LambdaDeviceMount {
  Path?: string;
  Permission?: string;
  AddGroupOwner?: boolean;
}

export interface EvaluateOnExit {
  Action: string;
  OnExitCode?: string;
  OnReason?: string;
  OnStatusReason?: string;
}

export interface AWS_ApiGateway_Stage____AccessLogSetting {
  DestinationArn?: string;
  Format?: string;
}

export interface ReplaceDefaultPolicyVersionParams {
  TemplateName: string;
}

export interface FrequencyBandwidth {
  Value?: number;
  Units?: string;
}

export interface LoadBasedAutoScaling {
  DownScaling?: AutoScalingThresholds;
  Enable?: boolean;
  UpScaling?: AutoScalingThresholds;
}

export interface StatusCodes {
  Items: Array<number>;
  Quantity: number;
}

export interface AWS_Batch_JobDefinition____Ulimit {
  SoftLimit: number;
  HardLimit: number;
  Name: string;
}

export type SshPublicKey = string;

export interface AWS_Glue_Trigger____Predicate {
  Logical?: string;
  Conditions?: Array<AWS_Glue_Trigger____Condition>;
}

export interface AWS_IAM_Group____Policy {
  PolicyDocument: any;
  PolicyName: string;
}

export interface AWS_Glue_Table____Order {
  Column: string;
  SortOrder: number;
}

export interface S3Source {
  DataSourceArn: string;
  InputColumns: Array<InputColumn>;
  UploadSettings?: UploadSettings;
}

export interface ElasticsearchRetryOptions {
  DurationInSeconds?: number;
}

export interface HttpAuthorization {
  Sigv4?: SigV4Authorization;
}

export interface SSESpecification {
  KMSMasterKeyId?: string;
  SSEEnabled: boolean;
  SSEType?: string;
}

export interface AWS_Route53_RecordSetGroup____AliasTarget {
  DNSName: string;
  EvaluateTargetHealth?: boolean;
  HostedZoneId: string;
}

export interface FleetLaunchTemplateOverridesRequest {
  WeightedCapacity?: number;
  Placement?: AWS_EC2_EC2Fleet____Placement;
  Priority?: number;
  AvailabilityZone?: string;
  SubnetId?: string;
  InstanceType?: string;
  MaxPrice?: string;
}

export interface AWS_Amplify_Branch____EnvironmentVariable {
  Value: string;
  Name: string;
}

export interface AWS_CloudFront_OriginRequestPolicy____QueryStringsConfig {
  QueryStringBehavior: string;
  QueryStrings?: Array<string>;
}

export interface AWS_Batch_JobDefinition____LinuxParameters {
  Swappiness?: number;
  Tmpfs?: Array<AWS_Batch_JobDefinition____Tmpfs>;
  SharedMemorySize?: number;
  Devices?: Array<AWS_Batch_JobDefinition____Device>;
  InitProcessEnabled?: boolean;
  MaxSwap?: number;
}

export interface AWS_NetworkFirewall_RuleGroup____CustomAction {
  ActionName: string;
  ActionDefinition: AWS_NetworkFirewall_RuleGroup____ActionDefinition;
}

export interface TransformationConfiguration {
  Actions?: Array<string>;
  ContentTransformation?: any;
}

export interface WindowsConfiguration {
  SelfManagedActiveDirectoryConfiguration?: SelfManagedActiveDirectoryConfiguration;
  WeeklyMaintenanceStartTime?: string;
  ActiveDirectoryId?: string;
  DeploymentType?: string;
  Aliases?: Array<string>;
  ThroughputCapacity: number;
  CopyTagsToBackups?: boolean;
  DailyAutomaticBackupStartTime?: string;
  AutomaticBackupRetentionDays?: number;
  PreferredSubnetId?: string;
}

export interface BehaviorCriteria {
  ComparisonOperator?: string;
  Value?: MetricValue;
  DurationSeconds?: number;
  ConsecutiveDatapointsToAlarm?: number;
  ConsecutiveDatapointsToClear?: number;
  StatisticalThreshold?: StatisticalThreshold;
  MlDetectionConfig?: MachineLearningDetectionConfig;
}

export interface DataSourceErrorInfo {
  Type?: string;
  Message?: string;
}

export interface AWS_Glue_Partition____Column {
  Comment?: string;
  Type?: string;
  Name: string;
}

export interface AWS_ECS_Service____AwsVpcConfiguration {
  AssignPublicIp?: string;
  SecurityGroups?: Array<string>;
  Subnets?: Array<string>;
}

export interface S3LogsConfig {
  Status: string;
  EncryptionDisabled?: boolean;
  Location?: string;
}

export interface GrpcRoute {
  Action: GrpcRouteAction;
  Timeout?: AWS_AppMesh_Route____GrpcTimeout;
  RetryPolicy?: GrpcRetryPolicy;
  Match: GrpcRouteMatch;
}

export interface ListenerTlsCertificate {
  SDS?: ListenerTlsSdsCertificate;
  ACM?: ListenerTlsAcmCertificate;
  File?: ListenerTlsFileCertificate;
}

export interface VpcConnectionProperties {
  VpcConnectionArn: string;
}

export interface BackupSelectionResourceType {
  IamRoleArn: string;
  ListOfTags?: Array<ConditionResourceType>;
  Resources?: Array<string>;
  SelectionName: string;
}

export interface AWS_Greengrass_ResourceDefinition____GroupOwnerSetting {
  AutoAddGroupOwner: boolean;
  GroupOwner?: string;
}

export interface AWS_SageMaker_DataQualityJobDefinition____S3Output {
  LocalPath: string;
  S3UploadMode?: string;
  S3Uri: string;
}

export interface JMXPrometheusExporter {
  JMXURL?: string;
  HostPort?: string;
  PrometheusPort?: string;
}

export interface CognitoOptions {
  Enabled?: boolean;
  IdentityPoolId?: string;
  RoleArn?: string;
  UserPoolId?: string;
}

export interface UserPoolConfig {
  AppIdClientRegex?: string;
  UserPoolId?: string;
  AwsRegion?: string;
  DefaultAction?: string;
}

export interface MemberDefinition {
  CognitoMemberDefinition: CognitoMemberDefinition;
}

export interface KMSEncryptionConfig {
  AWSKMSKeyARN: string;
}

export interface ConfigurationProperties {
  Description?: string;
  Key: boolean;
  Name: string;
  Queryable?: boolean;
  Required: boolean;
  Secret: boolean;
  Type?: string;
}

export interface AWS_AppMesh_Route____TcpTimeout {
  Idle?: AWS_AppMesh_Route____Duration;
}

export interface AWS_S3Outposts_Endpoint____NetworkInterface {
  NetworkInterfaceId: string;
}

export interface SpotFleetMonitoring {
  Enabled?: boolean;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____VpcConfig {
  SecurityGroupIds: Array<string>;
  Subnets: Array<string>;
}

export type AWS_S3_StorageLens____Encryption = undefined;

export interface S3Logs {
  S3BucketName?: string;
  S3KeyPrefix?: string;
}

export interface EncryptionKey {
  Id: string;
  Type: string;
}

export interface Sample {
  Size?: number;
  Type: string;
}

export interface OnEnter {
  Events?: Array<Event>;
}

export interface DynamoDBConfig {
  TableName: string;
  AwsRegion: string;
  Versioned?: boolean;
  DeltaSyncConfig?: DeltaSyncConfig;
  UseCallerCredentials?: boolean;
}

export interface AWS_EC2_LaunchTemplate____HibernationOptions {
  Configured?: boolean;
}

export interface AWS_EMR_InstanceGroupConfig____VolumeSpecification {
  Iops?: number;
  SizeInGB: number;
  VolumeType: string;
}

export interface VirtualGatewayFileAccessLog {
  Path: string;
}

export interface ConfigurationItem {
  Type?: string;
  Parameters?: Array<ConfigurationParameter>;
}

export interface LogicalTable {
  Alias: string;
  DataTransforms?: Array<TransformOperation>;
  Source: LogicalTableSource;
}

export interface HttpHeaderConfig {
  Values?: Array<string>;
  HttpHeaderName?: string;
}

export interface AWS_GlobalAccelerator_EndpointGroup____EndpointConfiguration {
  EndpointId: string;
  Weight?: number;
  ClientIPPreservationEnabled?: boolean;
}

export interface AWS_FraudDetector_Detector____EventVariable {
  Arn?: string;
  Inline?: boolean;
  Name?: string;
  DataSource?: string;
  DataType?: string;
  DefaultValue?: string;
  VariableType?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface AWS_WAFRegional_SqlInjectionMatchSet____SqlInjectionMatchTuple {
  TextTransformation: string;
  FieldToMatch: AWS_WAFRegional_SqlInjectionMatchSet____FieldToMatch;
}

export interface AWS_RDS_OptionGroup____OptionSetting {
  Name?: string;
  Value?: string;
}

export interface Deployment {
  Description?: string;
  IgnoreApplicationStopFailures?: boolean;
  Revision: RevisionLocation;
}

export interface CertificateAuthenticationRequest {
  ClientRootCertificateChainArn: string;
}

export interface KernelSpec {
  DisplayName?: string;
  Name: string;
}

export interface AWS_GlobalAccelerator_Listener____PortRange {
  FromPort: number;
  ToPort: number;
}

export interface IEMap {
  ACCOUNT?: Array<string>;
  ORGUNIT?: Array<string>;
}

export interface DynamoDBTarget {
  Path?: string;
}

export interface AWS_KinesisAnalytics_ApplicationOutput____DestinationSchema {
  RecordFormatType?: string;
}

export interface AWS_ECS_Service____NetworkConfiguration {
  AwsvpcConfiguration?: AWS_ECS_Service____AwsVpcConfiguration;
}

export interface ReshardingConfiguration {
  NodeGroupId?: string;
  PreferredAvailabilityZones?: Array<string>;
}

export interface AWS_DataBrew_Dataset____DataCatalogInputDefinition {
  CatalogId?: string;
  DatabaseName?: string;
  TableName?: string;
  TempDirectory?: AWS_DataBrew_Dataset____S3Location;
}

export interface DefaultRetention {
  Days?: number;
  Mode?: string;
  Years?: number;
}

export interface AttachmentsSource {
  Key?: string;
  Values?: Array<string>;
  Name?: string;
}

export interface DynamoDbSettings {
  ServiceAccessRoleArn?: string;
}

export interface ChannelStorage {
  CustomerManagedS3?: AWS_IoTAnalytics_Channel____CustomerManagedS3;
  ServiceManagedS3?: AWS_IoTAnalytics_Channel____ServiceManagedS3;
}

export interface MaintenanceWindowRunCommandParameters {
  TimeoutSeconds?: number;
  Comment?: string;
  OutputS3KeyPrefix?: string;
  Parameters?: any;
  DocumentHashType?: string;
  ServiceRoleArn?: string;
  NotificationConfig?: NotificationConfig;
  OutputS3BucketName?: string;
  DocumentHash?: string;
}

export interface GroupVersion {
  LoggerDefinitionVersionArn?: string;
  DeviceDefinitionVersionArn?: string;
  FunctionDefinitionVersionArn?: string;
  CoreDefinitionVersionArn?: string;
  ResourceDefinitionVersionArn?: string;
  ConnectorDefinitionVersionArn?: string;
  SubscriptionDefinitionVersionArn?: string;
}

export interface CustomizedLoadMetricSpecification {
  MetricName: string;
  Statistic: string;
  Dimensions?: Array<AWS_AutoScalingPlans_ScalingPlan____MetricDimension>;
  Unit?: string;
  Namespace: string;
}

export interface ModelExplainabilityBaselineConfig {
  BaseliningJobName?: string;
  ConstraintsResource?: AWS_SageMaker_ModelExplainabilityJobDefinition____ConstraintsResource;
}

export interface BackupRuleResourceType {
  RuleName: string;
  TargetBackupVault: string;
  StartWindowMinutes?: number;
  CompletionWindowMinutes?: number;
  ScheduleExpression?: string;
  RecoveryPointTags?: Record<string, string>;
  CopyActions?: Array<CopyActionResourceType>;
  Lifecycle?: LifecycleResourceType;
  EnableContinuousBackup?: boolean;
}

export interface AWS_ECS_TaskDefinition____Tmpfs {
  ContainerPath?: string;
  MountOptions?: Array<string>;
  Size: number;
}

export interface AccountRecoverySetting {
  RecoveryMechanisms?: Array<RecoveryOption>;
}

export interface AWS_WAFv2_WebACL____Rule {
  Name: string;
  Priority: number;
  Statement: AWS_WAFv2_WebACL____Statement;
  Action?: AWS_WAFv2_WebACL____RuleAction;
  OverrideAction?: OverrideAction;
  RuleLabels?: Array<AWS_WAFv2_WebACL____Label>;
  VisibilityConfig: AWS_WAFv2_WebACL____VisibilityConfig;
}

export interface AlarmMetric {
  AlarmMetricName: string;
}

export interface GatewayRouteVirtualService {
  VirtualServiceName: string;
}

export interface AWS_EMR_InstanceGroupConfig____EbsConfiguration {
  EbsBlockDeviceConfigs?: Array<AWS_EMR_InstanceGroupConfig____EbsBlockDeviceConfig>;
  EbsOptimized?: boolean;
}

export interface WebhookFilter {
  Pattern: string;
  Type: string;
  ExcludeMatchedPattern?: boolean;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____MonitoringOutput {
  S3Output: AWS_SageMaker_ModelExplainabilityJobDefinition____S3Output;
}

export interface OutputFormatConfiguration {
  Serializer?: Serializer;
}

export interface AWS_Greengrass_FunctionDefinitionVersion____Environment {
  Variables?: any;
  Execution?: AWS_Greengrass_FunctionDefinitionVersion____Execution;
  ResourceAccessPolicies?: Array<AWS_Greengrass_FunctionDefinitionVersion____ResourceAccessPolicy>;
  AccessSysfs?: boolean;
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule____ForwardConfig {
  TargetGroupStickinessConfig?: AWS_ElasticLoadBalancingV2_ListenerRule____TargetGroupStickinessConfig;
  TargetGroups?: Array<AWS_ElasticLoadBalancingV2_ListenerRule____TargetGroupTuple>;
}

export interface TemplateSourceEntity {
  SourceAnalysis?: TemplateSourceAnalysis;
  SourceTemplate?: TemplateSourceTemplate;
}

export interface OriginGroupFailoverCriteria {
  StatusCodes: StatusCodes;
}

export interface TimeToLiveSpecification {
  AttributeName: string;
  Enabled: boolean;
}

export interface TransformOperation {
  TagColumnOperation?: TagColumnOperation;
  FilterOperation?: FilterOperation;
  CastColumnTypeOperation?: CastColumnTypeOperation;
  CreateColumnsOperation?: CreateColumnsOperation;
  RenameColumnOperation?: RenameColumnOperation;
  ProjectOperation?: ProjectOperation;
}

export interface AWS_KinesisAnalyticsV2_Application____RecordColumn {
  Mapping?: string;
  SqlType: string;
  Name: string;
}

export interface NotificationWithSubscribers {
  Subscribers: Array<AWS_Budgets_Budget____Subscriber>;
  Notification: Notification;
}

export interface ParameterAttribute {
  Key: string;
  StringValue: string;
}

export interface NotificationFilter {
  S3Key: S3KeyFilter;
}

export interface RedshiftParameters {
  ClusterId?: string;
  Port?: number;
  Database: string;
  Host?: string;
}

export interface AWS_SageMaker_DataQualityJobDefinition____StoppingCondition {
  MaxRuntimeInSeconds: number;
}

export interface SqsParameters {
  MessageGroupId: string;
}

export interface DocDbSettings {
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface AWS_AppMesh_Route____HttpTimeout {
  PerRequest?: AWS_AppMesh_Route____Duration;
  Idle?: AWS_AppMesh_Route____Duration;
}

export interface ProvisioningArtifactProperties {
  Description?: string;
  DisableTemplateValidation?: boolean;
  Info: any;
  Name?: string;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____NetworkConfig {
  EnableInterContainerTrafficEncryption?: boolean;
  EnableNetworkIsolation?: boolean;
  VpcConfig?: AWS_SageMaker_ModelBiasJobDefinition____VpcConfig;
}

export interface ElasticsearchDestinationConfiguration {
  BufferingHints?: ElasticsearchBufferingHints;
  CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
  DomainARN?: string;
  IndexName: string;
  IndexRotationPeriod?: string;
  ProcessingConfiguration?: ProcessingConfiguration;
  RetryOptions?: ElasticsearchRetryOptions;
  RoleARN: string;
  S3BackupMode?: string;
  S3Configuration: AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration;
  ClusterEndpoint?: string;
  TypeName?: string;
  VpcConfiguration?: AWS_KinesisFirehose_DeliveryStream____VpcConfiguration;
}

export interface AWS_AppConfig_Application____Tags {
  Value?: string;
  Key?: string;
}

export interface AWS_AppSync_DataSource____AuthorizationConfig {
  AwsIamConfig?: AwsIamConfig;
  AuthorizationType: string;
}

export interface AWS_EC2_SecurityGroup____Ingress {
  CidrIp?: string;
  CidrIpv6?: string;
  Description?: string;
  FromPort?: number;
  IpProtocol: string;
  SourcePrefixListId?: string;
  SourceSecurityGroupId?: string;
  SourceSecurityGroupName?: string;
  SourceSecurityGroupOwnerId?: string;
  ToPort?: number;
}

export interface TableWithColumnsResource {
  ColumnNames?: Array<string>;
  DatabaseName?: string;
  CatalogId?: string;
  Name?: string;
  ColumnWildcard?: ColumnWildcard;
}

export interface RedshiftSourceConfig {
  ClusterIdentifier: string;
  DatabaseHost: string;
  DatabasePort: number;
  SecretManagerArn: string;
  DatabaseName: string;
  TableName: string;
  RoleArn: string;
  VpcConfiguration: AWS_LookoutMetrics_AnomalyDetector____VpcConfiguration;
}

export interface AWS_SageMaker_MonitoringSchedule____EndpointInput {
  EndpointName: string;
  LocalPath: string;
  S3DataDistributionType?: string;
  S3InputMode?: string;
}

export interface LambdaConfiguration {
  Event: string;
  Filter?: NotificationFilter;
  Function: string;
}

export interface AWS_ImageBuilder_ContainerRecipe____InstanceBlockDeviceMapping {
  DeviceName?: string;
  VirtualName?: string;
  NoDevice?: string;
  Ebs?: AWS_ImageBuilder_ContainerRecipe____EbsInstanceBlockDeviceSpecification;
}

export interface VirtualServiceSpec {
  Provider?: VirtualServiceProvider;
}

export interface AnalysisError {
  Type?: string;
  Message?: string;
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule____TargetGroupTuple {
  TargetGroupArn?: string;
  Weight?: number;
}

export interface AWS_WAF_Rule____Predicate {
  DataId: string;
  Negated: boolean;
  Type: string;
}

export interface LambdaLinuxProcessParams {
  IsolationMode?: string;
  ContainerParams?: LambdaContainerParams;
}

export interface CrossRegionCopyRetainRule {
  IntervalUnit: string;
  Interval: number;
}

export interface ClassicLoadBalancer {
  Name: string;
}

export interface RetryPolicy {
  MaximumEventAgeInSeconds?: number;
  MaximumRetryAttempts?: number;
}

export interface VPCOptions {
  SecurityGroupIds?: Array<string>;
  SubnetIds?: Array<string>;
}

export interface GoogleAnalyticsSourceProperties {
  Object: string;
}

export interface LaunchTemplateConfig {
  LaunchTemplateSpecification?: FleetLaunchTemplateSpecification;
  Overrides?: Array<AWS_EC2_SpotFleet____LaunchTemplateOverrides>;
}

export interface AWS_QuickSight_Dashboard____DateTimeParameter {
  Values: Array<string>;
  Name: string;
}

export interface AWS_KinesisAnalyticsV2_Application____CSVMappingParameters {
  RecordRowDelimiter: string;
  RecordColumnDelimiter: string;
}

export interface VirtualServiceBackend {
  ClientPolicy?: ClientPolicy;
  VirtualServiceName: string;
}

export interface PipelineTag {
  Key: string;
  Value: string;
}

export interface AWS_KinesisAnalytics_Application____MappingParameters {
  JSONMappingParameters?: AWS_KinesisAnalytics_Application____JSONMappingParameters;
  CSVMappingParameters?: AWS_KinesisAnalytics_Application____CSVMappingParameters;
}

export interface DomainNameConfiguration {
  SecurityPolicy?: string;
  EndpointType?: string;
  CertificateName?: string;
  CertificateArn?: string;
}

export interface HostedRotationLambda {
  RotationType: string;
  RotationLambdaName?: string;
  KmsKeyArn?: string;
  MasterSecretArn?: string;
  VpcSecurityGroupIds?: string;
  MasterSecretKmsKeyArn?: string;
  VpcSubnetIds?: string;
}

export interface Icmp {
  Code?: number;
  Type?: number;
}

export interface VirtualGatewayHttpConnectionPool {
  MaxConnections: number;
  MaxPendingRequests?: number;
}

export interface UserPoolAddOns {
  AdvancedSecurityMode?: string;
}

export interface UIColorPalette {
  Warning?: string;
  Accent?: string;
  AccentForeground?: string;
  SecondaryBackground?: string;
  DangerForeground?: string;
  PrimaryBackground?: string;
  Dimension?: string;
  SecondaryForeground?: string;
  WarningForeground?: string;
  DimensionForeground?: string;
  PrimaryForeground?: string;
  Success?: string;
  Danger?: string;
  SuccessForeground?: string;
  Measure?: string;
  MeasureForeground?: string;
}

export interface MixedInstancesPolicy {
  InstancesDistribution?: InstancesDistribution;
  LaunchTemplate: AWS_AutoScaling_AutoScalingGroup____LaunchTemplate;
}

export interface Activity {
  SelectAttributes?: SelectAttributes;
  Datastore?: Datastore;
  Filter?: AWS_IoTAnalytics_Pipeline____Filter;
  AddAttributes?: AddAttributes;
  Channel?: AWS_IoTAnalytics_Pipeline____Channel;
  DeviceShadowEnrich?: DeviceShadowEnrich;
  Math?: Math;
  Lambda?: AWS_IoTAnalytics_Pipeline____Lambda;
  DeviceRegistryEnrich?: DeviceRegistryEnrich;
  RemoveAttributes?: RemoveAttributes;
}

export interface IpAddressRequest {
  Ip?: string;
  SubnetId: string;
}

export interface SheetStyle {
  TileLayout?: TileLayoutStyle;
  Tile?: TileStyle;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____EndpointInput {
  EndpointName: string;
  LocalPath: string;
  S3DataDistributionType?: string;
  S3InputMode?: string;
  StartTimeOffset?: string;
  EndTimeOffset?: string;
  FeaturesAttribute?: string;
  InferenceAttribute?: string;
  ProbabilityAttribute?: string;
  ProbabilityThresholdAttribute?: number;
}

export interface InstanceMarketOptions {
  SpotOptions?: SpotOptions;
  MarketType?: string;
}

export interface ActionDeclaration {
  ActionTypeId: ActionTypeId;
  Configuration?: any;
  InputArtifacts?: Array<InputArtifact>;
  Name: string;
  Namespace?: string;
  OutputArtifacts?: Array<OutputArtifact>;
  Region?: string;
  RoleArn?: string;
  RunOrder?: number;
}

export interface AWS_Redshift_ClusterParameterGroup____Parameter {
  ParameterName: string;
  ParameterValue: string;
}

export interface BuildStatusConfig {
  Context?: string;
  TargetUrl?: string;
}

export interface AWS_EMR_InstanceFleetConfig____VolumeSpecification {
  Iops?: number;
  SizeInGB: number;
  VolumeType: string;
}

export interface SlackConnectorProfileCredentials {
  ClientId: string;
  ClientSecret: string;
  AccessToken?: string;
  ConnectorOAuthRequest?: ConnectorOAuthRequest;
}

export interface AWS_EC2_LaunchTemplate____CreditSpecification {
  CpuCredits?: string;
}

export interface AWS_ECS_Service____CapacityProviderStrategyItem {
  Base?: number;
  CapacityProvider?: string;
  Weight?: number;
}

export interface ServerSideEncryptionRule {
  BucketKeyEnabled?: boolean;
  ServerSideEncryptionByDefault?: ServerSideEncryptionByDefault;
}

export interface JoinInstruction {
  OnClause: string;
  Type: string;
  LeftJoinKeyProperties?: JoinKeyProperties;
  LeftOperand: string;
  RightOperand: string;
  RightJoinKeyProperties?: JoinKeyProperties;
}

export interface AWS_WAFRegional_WebACL____Rule {
  Action: AWS_WAFRegional_WebACL____Action;
  Priority: number;
  RuleId: string;
}

export interface JobSample {
  Mode?: string;
  Size?: number;
}

export interface AWS_ACMPCA_CertificateAuthority____OtherName {
  TypeId: string;
  Value: string;
}

export interface ExtendedKeyUsage {
  ExtendedKeyUsageType?: string;
  ExtendedKeyUsageObjectIdentifier?: string;
}

export interface AWS_Glue_Partition____StorageDescriptor {
  StoredAsSubDirectories?: boolean;
  Parameters?: any;
  BucketColumns?: Array<string>;
  NumberOfBuckets?: number;
  OutputFormat?: string;
  Columns?: Array<AWS_Glue_Partition____Column>;
  SerdeInfo?: AWS_Glue_Partition____SerdeInfo;
  SortColumns?: Array<AWS_Glue_Partition____Order>;
  Compressed?: boolean;
  SchemaReference?: AWS_Glue_Partition____SchemaReference;
  SkewedInfo?: AWS_Glue_Partition____SkewedInfo;
  InputFormat?: string;
  Location?: string;
}

export interface AWS_Glue_Trigger____Action {
  NotificationProperty?: AWS_Glue_Trigger____NotificationProperty;
  CrawlerName?: string;
  Timeout?: number;
  JobName?: string;
  Arguments?: any;
  SecurityConfiguration?: string;
}

export interface GlobalReplicationGroupMember {
  ReplicationGroupId?: string;
  ReplicationGroupRegion?: string;
  Role?: string;
}

export interface AWS_EC2_Instance____NetworkInterface {
  AssociatePublicIpAddress?: boolean;
  DeleteOnTermination?: boolean;
  Description?: string;
  DeviceIndex: string;
  GroupSet?: Array<string>;
  Ipv6AddressCount?: number;
  Ipv6Addresses?: Array<AWS_EC2_Instance____InstanceIpv6Address>;
  NetworkInterfaceId?: string;
  PrivateIpAddress?: string;
  PrivateIpAddresses?: Array<AWS_EC2_Instance____PrivateIpAddressSpecification>;
  SecondaryPrivateIpAddressCount?: number;
  SubnetId?: string;
}

export interface AWS_SageMaker_MonitoringSchedule____NetworkConfig {
  EnableInterContainerTrafficEncryption?: boolean;
  EnableNetworkIsolation?: boolean;
  VpcConfig?: AWS_SageMaker_MonitoringSchedule____VpcConfig;
}

export interface ApplicationSource {
  CloudFormationStackARN?: string;
  TagFilters?: Array<AWS_AutoScalingPlans_ScalingPlan____TagFilter>;
}

export interface AWS_KinesisAnalyticsV2_Application____RecordFormat {
  MappingParameters?: AWS_KinesisAnalyticsV2_Application____MappingParameters;
  RecordFormatType: string;
}

export interface TrackingConfig {
  Autotrack?: string;
}

export interface CrlConfiguration {
  Enabled?: boolean;
  ExpirationInDays?: number;
  CustomCname?: string;
  S3BucketName?: string;
}

export interface SybaseSettings {
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface AWS_WAFRegional_IPSet____IPSetDescriptor {
  Type: string;
  Value: string;
}

export interface HttpActionHeader {
  Value: string;
  Key: string;
}

export interface AWS_ECS_TaskDefinition____ContainerDefinition {
  Command?: Array<string>;
  Cpu?: number;
  DependsOn?: Array<ContainerDependency>;
  DisableNetworking?: boolean;
  DnsSearchDomains?: Array<string>;
  DnsServers?: Array<string>;
  DockerLabels?: Record<string, string>;
  DockerSecurityOptions?: Array<string>;
  EntryPoint?: Array<string>;
  Environment?: Array<KeyValuePair>;
  EnvironmentFiles?: Array<EnvironmentFile>;
  Essential?: boolean;
  ExtraHosts?: Array<HostEntry>;
  FirelensConfiguration?: FirelensConfiguration;
  HealthCheck?: AWS_ECS_TaskDefinition____HealthCheck;
  Hostname?: string;
  Image?: string;
  Links?: Array<string>;
  LinuxParameters?: AWS_ECS_TaskDefinition____LinuxParameters;
  LogConfiguration?: AWS_ECS_TaskDefinition____LogConfiguration;
  Memory?: number;
  MemoryReservation?: number;
  MountPoints?: Array<MountPoint>;
  Name?: string;
  PortMappings?: Array<AWS_ECS_TaskDefinition____PortMapping>;
  Privileged?: boolean;
  ReadonlyRootFilesystem?: boolean;
  RepositoryCredentials?: RepositoryCredentials;
  ResourceRequirements?: Array<AWS_ECS_TaskDefinition____ResourceRequirement>;
  Secrets?: Array<AWS_ECS_TaskDefinition____Secret>;
  StartTimeout?: number;
  StopTimeout?: number;
  Ulimits?: Array<AWS_ECS_TaskDefinition____Ulimit>;
  User?: string;
  VolumesFrom?: Array<VolumeFrom>;
  WorkingDirectory?: string;
  Interactive?: boolean;
  PseudoTerminal?: boolean;
  SystemControls?: Array<SystemControl>;
}

export interface MaintenanceWindowLambdaParameters {
  ClientContext?: string;
  Qualifier?: string;
  Payload?: string;
}

export interface AWS_Greengrass_ResourceDefinition____LocalDeviceResourceData {
  SourcePath: string;
  GroupOwnerSetting?: AWS_Greengrass_ResourceDefinition____GroupOwnerSetting;
}

export interface ModelQualityAppSpecification {
  ContainerArguments?: Array<string>;
  ContainerEntrypoint?: Array<string>;
  ImageUri: string;
  PostAnalyticsProcessorSourceUri?: string;
  RecordPreprocessorSourceUri?: string;
  Environment?: AWS_SageMaker_ModelQualityJobDefinition____Environment;
  ProblemType: string;
}

export interface AWS_WAFv2_RuleGroup____CustomResponseBody {
  ContentType: string;
  Content: string;
}

export interface OutlierDetection {
  MaxEjectionPercent: number;
  BaseEjectionDuration: AWS_AppMesh_VirtualNode____Duration;
  MaxServerErrors: number;
  Interval: AWS_AppMesh_VirtualNode____Duration;
}

export interface FargatePlatformConfiguration {
  PlatformVersion?: string;
}

export interface ParameterObject {
  Attributes: Array<ParameterAttribute>;
  Id: string;
}

export interface AWS_LookoutMetrics_AnomalyDetector____Metric {
  MetricName: string;
  AggregationFunction: string;
  Namespace?: string;
}

export interface VeevaSourceProperties {
  Object: string;
}

export interface StageDeclaration {
  Actions: Array<ActionDeclaration>;
  Blockers?: Array<BlockerDeclaration>;
  Name: string;
}

export interface AWS_EMR_Cluster____ScalingConstraints {
  MaxCapacity: number;
  MinCapacity: number;
}

export interface AWS_ElasticLoadBalancingV2_Listener____RedirectConfig {
  Path?: string;
  Query?: string;
  Port?: string;
  Host?: string;
  Protocol?: string;
  StatusCode: string;
}

export interface CrossRegionCopyRule {
  TargetRegion?: string;
  Target?: string;
  Encrypted: boolean;
  CmkArn?: string;
  RetainRule?: CrossRegionCopyRetainRule;
  CopyTags?: boolean;
}

export interface AWS_AutoScaling_AutoScalingGroup____NotificationConfiguration {
  NotificationTypes?: Array<string>;
  TopicARN: string;
}

export interface OutputColumn {
  Type?: string;
  Description?: string;
  Name?: string;
}

export interface DeploymentCircuitBreaker {
  Enable: boolean;
  Rollback: boolean;
}

export interface Monitoring {
  Enabled?: boolean;
}

export interface Timeout {
  AttemptDurationSeconds?: number;
}

export interface RepublishAction {
  Qos?: number;
  Topic: string;
  RoleArn: string;
}

export interface AWS_Glue_Table____SkewedInfo {
  SkewedColumnNames?: Array<string>;
  SkewedColumnValues?: Array<string>;
  SkewedColumnValueLocationMaps?: any;
}

export interface DnsRecord {
  Type: string;
  TTL: number;
}

export interface AuditNotificationTarget {
  TargetArn?: string;
  RoleArn?: string;
  Enabled?: boolean;
}

export interface HttpGatewayRouteMatch {
  Prefix: string;
}

export interface AWS_Greengrass_DeviceDefinition____Device {
  SyncShadow?: boolean;
  ThingArn: string;
  Id: string;
  CertificateArn: string;
}

export interface AWS_Config_ConfigRule____Scope {
  ComplianceResourceId?: string;
  ComplianceResourceTypes?: Array<string>;
  TagKey?: string;
  TagValue?: string;
}

export interface OrganizationManagedRuleMetadata {
  TagKeyScope?: string;
  TagValueScope?: string;
  Description?: string;
  ResourceIdScope?: string;
  RuleIdentifier: string;
  ResourceTypesScope?: Array<string>;
  MaximumExecutionFrequency?: string;
  InputParameters?: string;
}

export interface AWS_WAF_XssMatchSet____FieldToMatch {
  Data?: string;
  Type: string;
}

export interface IntegrationResponse {
  ContentHandling?: string;
  ResponseParameters?: Record<string, string>;
  ResponseTemplates?: Record<string, string>;
  SelectionPattern?: string;
  StatusCode: string;
}

export interface ForwardedValues {
  Cookies?: Cookies;
  Headers?: Array<string>;
  QueryString: boolean;
  QueryStringCacheKeys?: Array<string>;
}

export interface AWS_EC2_EC2Fleet____Placement {
  GroupName?: string;
  Tenancy?: string;
  SpreadDomain?: string;
  PartitionNumber?: number;
  AvailabilityZone?: string;
  Affinity?: string;
  HostId?: string;
  HostResourceGroupArn?: string;
}

export interface DeviceDefinitionVersion {
  Devices: Array<AWS_Greengrass_DeviceDefinition____Device>;
}

export interface AWS_EMR_Cluster____ScalingAction {
  Market?: string;
  SimpleScalingPolicyConfiguration: AWS_EMR_Cluster____SimpleScalingPolicyConfiguration;
}

export interface CompromisedCredentialsActionsType {
  EventAction: string;
}

export interface JmxExporter {
  EnabledInBroker: boolean;
}

export interface KeyValuePair {
  Name?: string;
  Value?: string;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____MonitoringOutput {
  S3Output: AWS_SageMaker_ModelQualityJobDefinition____S3Output;
}

export interface RedshiftSettings {
  SecretsManagerSecretId?: string;
  SecretsManagerAccessRoleArn?: string;
}

export interface AWS_Athena_WorkGroup____EncryptionConfiguration {
  EncryptionOption: string;
  KmsKey?: string;
}

export interface LaunchTemplateConfiguration {
  LaunchTemplateId?: string;
  AccountId?: string;
  SetDefaultVersion?: boolean;
}

export interface ColumnTag {
  ColumnGeographicRole?: string;
  ColumnDescription?: ColumnDescription;
}

export interface ExperimentTemplateAction {
  ActionId: string;
  Description?: string;
  Parameters?: Record<string, string>;
  Targets?: Record<string, string>;
  StartAfter?: Array<string>;
}

export interface Settings {
  EntityUrlTemplate?: string;
  ExecutionUrlTemplate?: string;
  RevisionUrlTemplate?: string;
  ThirdPartyConfigurationUrl?: string;
}

export interface AWS_S3_Bucket____AnalyticsConfiguration {
  Id: string;
  Prefix?: string;
  StorageClassAnalysis: StorageClassAnalysis;
  TagFilters?: Array<AWS_S3_Bucket____TagFilter>;
}

export interface Notification {
  ComparisonOperator: string;
  NotificationType: string;
  Threshold: number;
  ThresholdType?: string;
}

export interface CrossRegionCopyAction {
  Target: string;
  EncryptionConfiguration: AWS_DLM_LifecyclePolicy____EncryptionConfiguration;
  RetainRule?: CrossRegionCopyRetainRule;
}

export interface AWS_AutoScalingPlans_ScalingPlan____TargetTrackingConfiguration {
  ScaleOutCooldown?: number;
  TargetValue: number;
  PredefinedScalingMetricSpecification?: PredefinedScalingMetricSpecification;
  DisableScaleIn?: boolean;
  ScaleInCooldown?: number;
  EstimatedInstanceWarmup?: number;
  CustomizedScalingMetricSpecification?: CustomizedScalingMetricSpecification;
}

export interface AWS_Cassandra_Table____ProvisionedThroughput {
  ReadCapacityUnits: number;
  WriteCapacityUnits: number;
}

export interface AWS_KinesisAnalyticsV2_Application____JSONMappingParameters {
  RecordRowPath: string;
}

export interface HttpRouteHeader {
  Invert?: boolean;
  Name: string;
  Match?: HeaderMatchMethod;
}

export interface AWS_SageMaker_MonitoringSchedule____S3Output {
  LocalPath: string;
  S3UploadMode?: string;
  S3Uri: string;
}

export interface CodeContent {
  ZipFileContent?: string;
  S3ContentLocation?: S3ContentLocation;
  TextContent?: string;
}

export interface ConfigData {
  AntennaDownlinkConfig?: AntennaDownlinkConfig;
  TrackingConfig?: TrackingConfig;
  DataflowEndpointConfig?: DataflowEndpointConfig;
  AntennaDownlinkDemodDecodeConfig?: AntennaDownlinkDemodDecodeConfig;
  AntennaUplinkConfig?: AntennaUplinkConfig;
  UplinkEchoConfig?: UplinkEchoConfig;
  S3RecordingConfig?: S3RecordingConfig;
}

export interface AWS_Glue_Table____StorageDescriptor {
  StoredAsSubDirectories?: boolean;
  Parameters?: any;
  BucketColumns?: Array<string>;
  NumberOfBuckets?: number;
  OutputFormat?: string;
  Columns?: Array<AWS_Glue_Table____Column>;
  SerdeInfo?: AWS_Glue_Table____SerdeInfo;
  SortColumns?: Array<AWS_Glue_Table____Order>;
  Compressed?: boolean;
  SchemaReference?: AWS_Glue_Table____SchemaReference;
  SkewedInfo?: AWS_Glue_Table____SkewedInfo;
  InputFormat?: string;
  Location?: string;
}

export interface EnableIoTLoggingParams {
  LogLevel: string;
  RoleArnForLogging: string;
}

export interface AWS_Budgets_BudgetsAction____Subscriber {
  Type: string;
  Address: string;
}

export interface AWS_Greengrass_SubscriptionDefinition____Subscription {
  Target: string;
  Id: string;
  Source: string;
  Subject: string;
}

export interface AWS_StepFunctions_StateMachine____S3Location {
  Bucket: string;
  Key: string;
  Version?: string;
}

export interface AWS_ApiGateway_Stage____MethodSetting {
  CacheDataEncrypted?: boolean;
  CacheTtlInSeconds?: number;
  CachingEnabled?: boolean;
  DataTraceEnabled?: boolean;
  HttpMethod?: string;
  LoggingLevel?: string;
  MetricsEnabled?: boolean;
  ResourcePath?: string;
  ThrottlingBurstLimit?: number;
  ThrottlingRateLimit?: number;
}

export interface ResourceDefinitionVersion {
  Resources: Array<AWS_Greengrass_ResourceDefinition____ResourceInstance>;
}

export interface AWS_DynamoDB_Table____ProvisionedThroughput {
  ReadCapacityUnits: number;
  WriteCapacityUnits: number;
}

export interface AWS_EC2_LaunchTemplate____Placement {
  GroupName?: string;
  Tenancy?: string;
  SpreadDomain?: string;
  PartitionNumber?: number;
  AvailabilityZone?: string;
  Affinity?: string;
  HostId?: string;
  HostResourceGroupArn?: string;
}

export interface HttpRequestMethodConfig {
  Values?: Array<string>;
}

export interface AWS_S3_Bucket____LoggingConfiguration {
  DestinationBucketName?: string;
  LogFilePrefix?: string;
}

export interface MasterUserOptions {
  MasterUserARN?: string;
  MasterUserName?: string;
  MasterUserPassword?: string;
}

export interface RoutingRule {
  RedirectRule: RedirectRule;
  RoutingRuleCondition?: RoutingRuleCondition;
}

export interface IdentityProviderDetails {
  InvocationRole: string;
  Url: string;
}

export interface NotifyConfigurationType {
  BlockEmail?: NotifyEmailType;
  ReplyTo?: string;
  SourceArn: string;
  NoActionEmail?: NotifyEmailType;
  From?: string;
  MfaEmail?: NotifyEmailType;
}

export interface AWS_IoTEvents_DetectorModel____AssetPropertyValue {
  Quality?: string;
  Timestamp?: AWS_IoTEvents_DetectorModel____AssetPropertyTimestamp;
  Value: AWS_IoTEvents_DetectorModel____AssetPropertyVariant;
}

export interface AWS_AppSync_Resolver____SyncConfig {
  ConflictHandler?: string;
  ConflictDetection: string;
  LambdaConflictHandlerConfig?: AWS_AppSync_Resolver____LambdaConflictHandlerConfig;
}

export interface AWS_Route53_RecordSet____GeoLocation {
  ContinentCode?: string;
  CountryCode?: string;
  SubdivisionCode?: string;
}

export interface CustomResponse {
  ResponseCode: number;
  CustomResponseBodyKey?: string;
  ResponseHeaders?: Array<CustomHTTPHeader>;
}

export interface AWS_Glue_Trigger____NotificationProperty {
  NotifyDelayAfter?: number;
}

export interface PortSet {
  Definition?: Array<string>;
}

export interface ScalingConfig {
  MinSize?: number;
  DesiredSize?: number;
  MaxSize?: number;
}

export interface AnalysisSecurityGroupRule {
  Cidr?: string;
  Direction?: string;
  SecurityGroupId?: string;
  PortRange?: AWS_EC2_NetworkInsightsAnalysis____PortRange;
  PrefixListId?: string;
  Protocol?: string;
}

export interface AWS_AutoScaling_ScalingPolicy____PredefinedMetricSpecification {
  PredefinedMetricType: string;
  ResourceLabel?: string;
}

export interface AWS_SageMaker_App____ResourceSpec {
  InstanceType?: string;
  SageMakerImageArn?: string;
  SageMakerImageVersionArn?: string;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____ClusterConfig {
  InstanceCount: number;
  InstanceType: string;
  VolumeKmsKeyId?: string;
  VolumeSizeInGB: number;
}

export interface EksInfo {
  Namespace: string;
}

export interface AWS_ApiGateway_DomainName____EndpointConfiguration {
  Types?: Array<string>;
}

export interface InstanceConfiguration {
  Image?: string;
  BlockDeviceMappings?: Array<AWS_ImageBuilder_ContainerRecipe____InstanceBlockDeviceMapping>;
}

export interface CoreDefinitionVersion {
  Cores: Array<AWS_Greengrass_CoreDefinition____Core>;
}

export interface AWS_ApplicationAutoScaling_ScalingPolicy____StepAdjustment {
  MetricIntervalLowerBound?: number;
  MetricIntervalUpperBound?: number;
  ScalingAdjustment: number;
}

export interface ConfigurationDetails {
  AlarmMetrics?: Array<AlarmMetric>;
  Logs?: Array<Log>;
  WindowsEvents?: Array<WindowsEvent>;
  Alarms?: Array<AWS_ApplicationInsights_Application____Alarm>;
  JMXPrometheusExporter?: JMXPrometheusExporter;
}

export interface TrendmicroConnectorProfileCredentials {
  ApiSecretKey: string;
}

export interface Deserializer {
  HiveJsonSerDe?: HiveJsonSerDe;
  OpenXJsonSerDe?: OpenXJsonSerDe;
}

export interface StepFunctionsAction {
  ExecutionNamePrefix?: string;
  StateMachineName: string;
  RoleArn: string;
}

export interface SpotFleetRequestConfigData {
  AllocationStrategy?: string;
  ExcessCapacityTerminationPolicy?: string;
  IamFleetRole: string;
  InstanceInterruptionBehavior?: string;
  InstancePoolsToUseCount?: number;
  LaunchSpecifications?: Array<SpotFleetLaunchSpecification>;
  LaunchTemplateConfigs?: Array<LaunchTemplateConfig>;
  LoadBalancersConfig?: LoadBalancersConfig;
  OnDemandAllocationStrategy?: string;
  OnDemandMaxTotalPrice?: string;
  OnDemandTargetCapacity?: number;
  ReplaceUnhealthyInstances?: boolean;
  SpotMaintenanceStrategies?: SpotMaintenanceStrategies;
  SpotMaxTotalPrice?: string;
  SpotPrice?: string;
  TargetCapacity: number;
  TerminateInstancesWithExpiration?: boolean;
  Type?: string;
  ValidFrom?: string;
  ValidUntil?: string;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____S3MachineLearningModelResourceData {
  OwnerSetting?: AWS_Greengrass_ResourceDefinitionVersion____ResourceDownloadOwnerSetting;
  DestinationPath: string;
  S3Uri: string;
}

export interface AWS_EMR_Cluster____SimpleScalingPolicyConfiguration {
  AdjustmentType?: string;
  CoolDown?: number;
  ScalingAdjustment: number;
}

export interface S3BucketDestination {
  OutputSchemaVersion: string;
  Format: string;
  AccountId: string;
  Arn: string;
  Prefix?: string;
  Encryption?: AWS_S3_StorageLens____Encryption;
}

export interface AuditCheckConfigurations {
  AuthenticatedCognitoRoleOverlyPermissiveCheck?: AuditCheckConfiguration;
  CaCertificateExpiringCheck?: AuditCheckConfiguration;
  CaCertificateKeyQualityCheck?: AuditCheckConfiguration;
  ConflictingClientIdsCheck?: AuditCheckConfiguration;
  DeviceCertificateExpiringCheck?: AuditCheckConfiguration;
  DeviceCertificateKeyQualityCheck?: AuditCheckConfiguration;
  DeviceCertificateSharedCheck?: AuditCheckConfiguration;
  IotPolicyOverlyPermissiveCheck?: AuditCheckConfiguration;
  IotRoleAliasAllowsAccessToUnusedServicesCheck?: AuditCheckConfiguration;
  IotRoleAliasOverlyPermissiveCheck?: AuditCheckConfiguration;
  LoggingDisabledCheck?: AuditCheckConfiguration;
  RevokedCaCertificateStillActiveCheck?: AuditCheckConfiguration;
  RevokedDeviceCertificateStillActiveCheck?: AuditCheckConfiguration;
  UnauthenticatedCognitoRoleOverlyPermissiveCheck?: AuditCheckConfiguration;
}

export interface LogConfig {
  CloudWatchLogsRoleArn?: string;
  ExcludeVerboseContent?: boolean;
  FieldLogLevel?: string;
}

export interface AWS_Batch_JobDefinition____Tmpfs {
  Size: number;
  ContainerPath: string;
  MountOptions?: Array<string>;
}

export interface AWS_SageMaker_Model____ImageConfig {
  RepositoryAccessMode: string;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____ConstraintsResource {
  S3Uri?: string;
}

export interface ClusterConfiguration {
  ExecuteCommandConfiguration?: ExecuteCommandConfiguration;
}

export interface AWS_S3_Bucket____EncryptionConfiguration {
  ReplicaKmsKeyID: string;
}

export interface AWS_ElasticLoadBalancingV2_Listener____FixedResponseConfig {
  ContentType?: string;
  StatusCode: string;
  MessageBody?: string;
}

export interface AWS_Events_Rule____Target {
  Arn: string;
  BatchParameters?: BatchParameters;
  DeadLetterConfig?: AWS_Events_Rule____DeadLetterConfig;
  EcsParameters?: EcsParameters;
  HttpParameters?: HttpParameters;
  Id: string;
  Input?: string;
  InputPath?: string;
  InputTransformer?: InputTransformer;
  KinesisParameters?: KinesisParameters;
  RedshiftDataParameters?: RedshiftDataParameters;
  RetryPolicy?: RetryPolicy;
  RoleArn?: string;
  RunCommandParameters?: RunCommandParameters;
  SqsParameters?: SqsParameters;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____S3Output {
  LocalPath: string;
  S3UploadMode?: string;
  S3Uri: string;
}

export interface SsmControls {
  ErrorPercentage?: number;
  ConcurrentExecutionRatePercentage?: number;
}

export interface CloudWatchLogsLogGroup {
  LogGroupArn?: string;
}

export type Criterion = undefined;

export interface Role {
  RoleArn?: string;
  RoleType?: string;
}

export interface VirtualGatewayHealthCheckPolicy {
  Path?: string;
  UnhealthyThreshold: number;
  Port?: number;
  HealthyThreshold: number;
  TimeoutMillis: number;
  Protocol: string;
  IntervalMillis: number;
}

export interface StorageInfo {
  EBSStorageInfo?: EBSStorageInfo;
}

export interface RdsHttpEndpointConfig {
  AwsRegion: string;
  Schema?: string;
  DatabaseName?: string;
  DbClusterIdentifier: string;
  AwsSecretStoreArn: string;
}

export interface TagColumnOperation {
  ColumnName: string;
  Tags: Array<ColumnTag>;
}

export interface AWS_Route53_RecordSet____AliasTarget {
  DNSName: string;
  EvaluateTargetHealth?: boolean;
  HostedZoneId: string;
}

export interface RepositoryTrigger {
  Events: Array<string>;
  Branches?: Array<string>;
  CustomData?: string;
  DestinationArn: string;
  Name: string;
}

export interface DynatraceSourceProperties {
  Object: string;
}

export interface AWS_WAFv2_RuleGroup____Label {
  Name: string;
}

export interface CustomRule {
  Condition?: string;
  Status?: string;
  Target: string;
  Source: string;
}

export interface RunConfig {
  TimeoutInSeconds?: number;
  MemoryInMB?: number;
  ActiveTracing?: boolean;
  EnvironmentVariables?: Record<string, string>;
}

export interface Math {
  Attribute?: string;
  Next?: string;
  Math?: string;
  Name?: string;
}

export interface KinesisStreamSourceConfiguration {
  KinesisStreamARN: string;
  RoleARN: string;
}

export interface XMLClassifier {
  RowTag: string;
  Classification: string;
  Name?: string;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____MappingParameters {
  JSONMappingParameters?: AWS_KinesisAnalytics_ApplicationReferenceDataSource____JSONMappingParameters;
  CSVMappingParameters?: AWS_KinesisAnalytics_ApplicationReferenceDataSource____CSVMappingParameters;
}

export interface RedshiftRetryOptions {
  DurationInSeconds?: number;
}

export interface AWS_ApiGatewayV2_RouteResponse____ParameterConstraints {
  Required: boolean;
}

export interface Task {
  SourceFields: Array<string>;
  ConnectorOperator?: ConnectorOperator;
  DestinationField?: string;
  TaskType: string;
  TaskProperties?: Array<TaskPropertiesObject>;
}

export interface AWS_Greengrass_ResourceDefinition____LocalVolumeResourceData {
  SourcePath: string;
  DestinationPath: string;
  GroupOwnerSetting?: AWS_Greengrass_ResourceDefinition____GroupOwnerSetting;
}

export interface AssessmentReportsDestination {
  Destination?: string;
  DestinationType?: string;
}

export interface PlacementType {
  AvailabilityZone: string;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____MonitoringGroundTruthS3Input {
  S3Uri: string;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____MonitoringResources {
  ClusterConfig: AWS_SageMaker_ModelExplainabilityJobDefinition____ClusterConfig;
}

export interface NodeExporter {
  EnabledInBroker: boolean;
}

export interface RemoteAccess {
  SourceSecurityGroups?: Array<string>;
  Ec2SshKey: string;
}

export interface ModelQualityBaselineConfig {
  BaseliningJobName?: string;
  ConstraintsResource?: AWS_SageMaker_ModelQualityJobDefinition____ConstraintsResource;
}

export interface AWS_ElastiCache_CacheCluster____DestinationDetails {
  CloudWatchLogsDetails?: AWS_ElastiCache_CacheCluster____CloudWatchLogsDestinationDetails;
  KinesisFirehoseDetails?: AWS_ElastiCache_CacheCluster____KinesisFirehoseDestinationDetails;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____JSONMappingParameters {
  RecordRowPath: string;
}

export interface MetricSet {
  MetricSetName: string;
  MetricSetDescription?: string;
  MetricSource: MetricSource;
  MetricList: Array<AWS_LookoutMetrics_AnomalyDetector____Metric>;
  Offset?: number;
  TimestampColumn?: TimestampColumn;
  DimensionList?: Array<string>;
  MetricSetFrequency?: string;
  Timezone?: string;
}

export interface VotingPolicy {
  ApprovalThresholdPolicy?: ApprovalThresholdPolicy;
}

export interface AWS_S3Outposts_Bucket____LifecycleConfiguration {
  Rules: Array<AWS_S3Outposts_Bucket____Rule>;
}

export interface ScheduledAction {
  EndTime?: string;
  ScalableTargetAction?: ScalableTargetAction;
  Schedule: string;
  ScheduledActionName: string;
  StartTime?: string;
}

export interface AccessControlAttributeValue {
  Source: Array<string>;
}

export interface AWS_EC2_Instance____InstanceIpv6Address {
  Ipv6Address: string;
}

export interface OriginShield {
  Enabled?: boolean;
  OriginShieldRegion?: string;
}

export interface AssociationParameter {
  Key: string;
  Value: Array<string>;
}

export interface TopicRulePayload {
  RuleDisabled?: boolean;
  ErrorAction?: AWS_IoT_TopicRule____Action;
  Description?: string;
  AwsIotSqlVersion?: string;
  Actions: Array<AWS_IoT_TopicRule____Action>;
  Sql: string;
}

export interface PushSync {
  ApplicationArns?: Array<string>;
  RoleArn?: string;
}

export interface EBSStorageInfo {
  VolumeSize?: number;
}

export interface AWS_ECS_Service____ServiceRegistry {
  ContainerName?: string;
  ContainerPort?: number;
  Port?: number;
  RegistryArn?: string;
}

export interface WebsiteConfiguration {
  ErrorDocument?: string;
  IndexDocument?: string;
  RedirectAllRequestsTo?: RedirectAllRequestsTo;
  RoutingRules?: Array<RoutingRule>;
}

export interface CognitoIdentityProvider {
  ServerSideTokenCheck?: boolean;
  ProviderName?: string;
  ClientId?: string;
}

export interface CloudFormationCollectionFilter {
  StackNames?: Array<string>;
}

export interface LogPublishingOption {
  CloudWatchLogsLogGroupArn?: string;
  Enabled?: boolean;
}

export interface TileLayoutStyle {
  Gutter?: GutterStyle;
  Margin?: MarginStyle;
}

export interface AWS_ElastiCache_CacheCluster____CloudWatchLogsDestinationDetails {
  LogGroup?: string;
}

export interface AWSService {
  ServiceName?: string;
}

export interface ResourceConfiguration {
  VolumeSizeInGB: number;
  ComputeType: string;
}

export interface ConfigurationOptionSetting {
  Namespace: string;
  OptionName: string;
  ResourceName?: string;
  Value?: string;
}

export interface NodeRangeProperty {
  Container?: ContainerProperties;
  TargetNodes: string;
}

export interface VeevaConnectorProfileCredentials {
  Username: string;
  Password: string;
}

export interface KinesisParameters {
  PartitionKeyPath: string;
}

export interface AWS_Cognito_UserPool____Policies {
  PasswordPolicy?: PasswordPolicy;
}

export interface CloudwatchConfig {
  RoleArn: string;
}

export interface VeevaConnectorProfileProperties {
  InstanceUrl: string;
}

export interface RetryOptions {
  DurationInSeconds?: number;
}

export interface TlsValidationContextAcmTrust {
  CertificateAuthorityArns: Array<string>;
}

export interface ArtifactStore {
  EncryptionKey?: EncryptionKey;
  Location: string;
  Type: string;
}

export interface AWS_CodeGuruProfiler_ProfilingGroup____Channel {
  channelId?: string;
  channelUri: string;
}

export interface BlueGreenUpdatePolicy {
  MaximumExecutionTimeoutInSeconds?: number;
  TerminationWaitInSeconds?: number;
  TrafficRoutingConfiguration: TrafficRoutingConfig;
}

export interface EgressFilter {
  Type: string;
}

export interface StaticValue {
  Values?: Array<string>;
}

export interface TargetContainerRepository {
  Service?: string;
  RepositoryName?: string;
}

export interface AWS_SageMaker_MonitoringSchedule____MonitoringResources {
  ClusterConfig: AWS_SageMaker_MonitoringSchedule____ClusterConfig;
}

export interface AWS_SageMaker_UserProfile____UserSettings {
  ExecutionRole?: string;
  JupyterServerAppSettings?: AWS_SageMaker_UserProfile____JupyterServerAppSettings;
  KernelGatewayAppSettings?: AWS_SageMaker_UserProfile____KernelGatewayAppSettings;
  SecurityGroups?: Array<string>;
  SharingSettings?: AWS_SageMaker_UserProfile____SharingSettings;
}

export interface TriggeringDataset {
  DatasetName: string;
}

export interface AccountTakeoverRiskConfigurationType {
  Actions: AccountTakeoverActionsType;
  NotifyConfiguration?: NotifyConfigurationType;
}

export interface TransformParameters {
  TransformType: string;
  FindMatchesParameters?: FindMatchesParameters;
}

export interface TopicConfiguration {
  Event: string;
  Filter?: NotificationFilter;
  Topic: string;
}

export interface S3OriginConfig {
  OriginAccessIdentity?: string;
}

export interface AWS_EC2_Instance____EnclaveOptions {
  Enabled?: boolean;
}

export interface AWS_WAFv2_WebACL____RateBasedStatement {
  Limit: number;
  AggregateKeyType: string;
  ScopeDownStatement?: AWS_WAFv2_WebACL____Statement;
  ForwardedIPConfig?: AWS_WAFv2_WebACL____ForwardedIPConfiguration;
}

export interface AWS_AmazonMQ_Configuration____TagsEntry {
  Value: string;
  Key: string;
}

export interface AWS_FraudDetector_EventType____EventVariable {
  Arn?: string;
  Inline?: boolean;
  Name?: string;
  DataSource?: string;
  DataType?: string;
  DefaultValue?: string;
  VariableType?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface ClientPolicy {
  TLS?: ClientPolicyTls;
}

export interface AWS_WAF_SizeConstraintSet____FieldToMatch {
  Data?: string;
  Type: string;
}

export interface ExperimentTemplateTargetFilter {
  Path: string;
  Values: Array<string>;
}

export interface ShareRule {
  TargetAccounts?: Array<string>;
  UnshareIntervalUnit?: string;
  UnshareInterval?: number;
}

export interface AddAttributes {
  Next?: string;
  Attributes?: any;
  Name?: string;
}

export interface DatetimeOptions {
  Format: string;
  TimezoneOffset?: string;
  LocaleCode?: string;
}

export interface AWS_AuditManager_Assessment____Scope {
  AwsAccounts?: Array<AWSAccount>;
  AwsServices?: Array<AWSService>;
}

export interface CustomEmailSender {
  LambdaArn?: string;
  LambdaVersion?: string;
}

export interface BlockDevice {
  DeleteOnTermination?: boolean;
  Encrypted?: boolean;
  Iops?: number;
  SnapshotId?: string;
  VolumeSize?: number;
  VolumeType?: string;
}

export interface AutoScalingThresholds {
  CpuThreshold?: number;
  IgnoreMetricsTime?: number;
  InstanceCount?: number;
  LoadThreshold?: number;
  MemoryThreshold?: number;
  ThresholdsWaitTime?: number;
}

export interface HttpGatewayRoute {
  Action: HttpGatewayRouteAction;
  Match: HttpGatewayRouteMatch;
}

export interface ActionParams {
  AddThingsToThingGroupParams?: AddThingsToThingGroupParams;
  EnableIoTLoggingParams?: EnableIoTLoggingParams;
  PublishFindingToSnsParams?: PublishFindingToSnsParams;
  ReplaceDefaultPolicyVersionParams?: ReplaceDefaultPolicyVersionParams;
  UpdateCACertificateParams?: UpdateCACertificateParams;
  UpdateDeviceCertificateParams?: UpdateDeviceCertificateParams;
}

export interface DataCaptureConfig {
  CaptureOptions: Array<CaptureOption>;
  KmsKeyId?: string;
  DestinationS3Uri: string;
  InitialSamplingPercentage: number;
  CaptureContentTypeHeader?: CaptureContentTypeHeader;
  EnableCapture?: boolean;
}

export interface TaskPropertiesObject {
  Key: string;
  Value: string;
}

export interface ResourceQuery {
  Type?: string;
  Query?: Query;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____S3ReferenceDataSource {
  BucketARN: string;
  FileKey: string;
}

export interface PostgreSqlParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface AWS_ACMPCA_CertificateAuthority____GeneralName {
  OtherName?: AWS_ACMPCA_CertificateAuthority____OtherName;
  Rfc822Name?: string;
  DnsName?: string;
  DirectoryName?: AWS_ACMPCA_CertificateAuthority____Subject;
  EdiPartyName?: AWS_ACMPCA_CertificateAuthority____EdiPartyName;
  UniformResourceIdentifier?: string;
  IpAddress?: string;
  RegisteredId?: string;
}

export interface AWS_KinesisAnalytics_Application____RecordFormat {
  MappingParameters?: AWS_KinesisAnalytics_Application____MappingParameters;
  RecordFormatType: string;
}

export interface AWS_S3_Bucket____TagFilter {
  Key: string;
  Value: string;
}

export interface InstanceDefinition {
  InstanceType: string;
  WeightedCapacity?: string;
}

export interface ExecutionControls {
  SsmControls?: SsmControls;
}

export interface AWS_WAF_SizeConstraintSet____SizeConstraint {
  ComparisonOperator: string;
  FieldToMatch: AWS_WAF_SizeConstraintSet____FieldToMatch;
  Size: number;
  TextTransformation: string;
}

export interface AWS_GuardDuty_Filter____Condition {
  Lt?: number;
  Gte?: number;
  Neq?: Array<string>;
  Eq?: Array<string>;
  Lte?: number;
}

export type Admins = AWS_LakeFormation_DataLakeSettings____DataLakePrincipal[];

export interface ClientTlsCertificate {
  SDS?: ListenerTlsSdsCertificate;
  File?: ListenerTlsFileCertificate;
}

export interface RuntimeConfiguration {
  GameSessionActivationTimeoutSeconds?: number;
  MaxConcurrentGameSessionActivations?: number;
  ServerProcesses?: Array<ServerProcess>;
}

export interface Ipv6Add {
  Ipv6Address?: string;
}

export interface AWS_EC2_Instance____LicenseSpecification {
  LicenseConfigurationArn: string;
}

export interface ConditionExpression {
  Condition: string;
  Value?: string;
  TargetColumn: string;
}

export interface PublishFindingToSnsParams {
  TopicArn: string;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____MonitoringOutputConfig {
  KmsKeyId?: string;
  MonitoringOutputs: Array<AWS_SageMaker_ModelExplainabilityJobDefinition____MonitoringOutput>;
}

export interface AWS_MWAA_Environment____LoggingConfiguration {
  DagProcessingLogs?: ModuleLoggingConfiguration;
  SchedulerLogs?: ModuleLoggingConfiguration;
  WebserverLogs?: ModuleLoggingConfiguration;
  WorkerLogs?: ModuleLoggingConfiguration;
  TaskLogs?: ModuleLoggingConfiguration;
}

export interface EngineVersion {
  SelectedEngineVersion?: string;
  EffectiveEngineVersion?: string;
}

export interface ListenerTlsValidationContextTrust {
  SDS?: TlsValidationContextSdsTrust;
  File?: TlsValidationContextFileTrust;
}

export interface ThrottleSettings {
  BurstLimit?: number;
  RateLimit?: number;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____VpcConfig {
  SecurityGroupIds: Array<string>;
  Subnets: Array<string>;
}

export interface SlackConnectorProfileProperties {
  InstanceUrl: string;
}

export interface MarketoConnectorProfileProperties {
  InstanceUrl: string;
}

export interface AWS_MSK_Cluster____Firehose {
  DeliveryStream?: string;
  Enabled: boolean;
}

export interface LambdaEventSource {
  Topic?: string;
  Type?: string;
}

export interface AWS_SageMaker_MonitoringSchedule____StoppingCondition {
  MaxRuntimeInSeconds: number;
}

export interface AWS_AmazonMQ_Broker____ConfigurationId {
  Revision: number;
  Id: string;
}

export interface SsmAssociation {
  AssociationParameters?: Array<AssociationParameter>;
  DocumentName: string;
}

export interface KinesisStreamConfig {
  RoleArn: string;
  StreamArn: string;
}

export interface ExcludedRule {
  Name: string;
}

export interface RdsParameters {
  InstanceId: string;
  Database: string;
}

export interface PriorityConfiguration {
  PriorityOrder?: Array<string>;
  LocationOrder?: Array<string>;
}

export interface AWS_Lambda_EventSourceMapping____DestinationConfig {
  OnFailure?: AWS_Lambda_EventSourceMapping____OnFailure;
}

export interface AWS_Greengrass_ResourceDefinition____ResourceInstance {
  ResourceDataContainer: AWS_Greengrass_ResourceDefinition____ResourceDataContainer;
  Id: string;
  Name: string;
}

export interface ApplicationConfiguration {
  ApplicationCodeConfiguration?: ApplicationCodeConfiguration;
  EnvironmentProperties?: EnvironmentProperties;
  FlinkApplicationConfiguration?: FlinkApplicationConfiguration;
  SqlApplicationConfiguration?: SqlApplicationConfiguration;
  ApplicationSnapshotConfiguration?: ApplicationSnapshotConfiguration;
}

export interface VirtualGatewayTlsValidationContextAcmTrust {
  CertificateAuthorityArns: Array<string>;
}

export interface EngineAttribute {
  Value?: string;
  Name?: string;
}

export interface AWS_Greengrass_FunctionDefinition____Function {
  FunctionArn: string;
  FunctionConfiguration: AWS_Greengrass_FunctionDefinition____FunctionConfiguration;
  Id: string;
}

export interface AWS_Glue_Partition____SkewedInfo {
  SkewedColumnNames?: Array<string>;
  SkewedColumnValues?: Array<string>;
  SkewedColumnValueLocationMaps?: any;
}

export interface AWS_FraudDetector_EventType____Label {
  Arn?: string;
  Inline?: boolean;
  Name?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface Projection {
  NonKeyAttributes?: Array<string>;
  ProjectionType?: string;
}

export interface AWS_EC2_LaunchTemplate____NetworkInterface {
  Description?: string;
  PrivateIpAddress?: string;
  PrivateIpAddresses?: Array<PrivateIpAdd>;
  SecondaryPrivateIpAddressCount?: number;
  DeviceIndex?: number;
  SubnetId?: string;
  Ipv6Addresses?: Array<Ipv6Add>;
  AssociatePublicIpAddress?: boolean;
  NetworkInterfaceId?: string;
  NetworkCardIndex?: number;
  InterfaceType?: string;
  AssociateCarrierIpAddress?: boolean;
  Ipv6AddressCount?: number;
  Groups?: Array<string>;
  DeleteOnTermination?: boolean;
}

export interface AWS_NetworkManager_Site____Location {
  Address?: string;
  Latitude?: string;
  Longitude?: string;
}

export interface AWS_WAFRegional_XssMatchSet____FieldToMatch {
  Type: string;
  Data?: string;
}

export interface EfsVolumeConfiguration {
  TransitEncryption?: string;
  AuthorizationConfig?: AWS_Batch_JobDefinition____AuthorizationConfig;
  FileSystemId: string;
  RootDirectory?: string;
  TransitEncryptionPort?: number;
}

export interface AWS_SageMaker_DataQualityJobDefinition____NetworkConfig {
  EnableInterContainerTrafficEncryption?: boolean;
  EnableNetworkIsolation?: boolean;
  VpcConfig?: AWS_SageMaker_DataQualityJobDefinition____VpcConfig;
}

export interface MonitoringInput {
  EndpointInput: AWS_SageMaker_MonitoringSchedule____EndpointInput;
}

export interface HttpRouteAction {
  WeightedTargets: Array<WeightedTarget>;
}

export interface AWS_SageMaker_DataQualityJobDefinition____EndpointInput {
  EndpointName: string;
  LocalPath: string;
  S3DataDistributionType?: string;
  S3InputMode?: string;
}

export interface AntennaUplinkConfig {
  SpectrumConfig?: UplinkSpectrumConfig;
  TargetEirp?: Eirp;
  TransmitDisabled?: boolean;
}

export interface InferenceExecutionConfig {
  Mode: string;
}

export interface FailoverConfig {
  State?: string;
  RecoveryWindow?: number;
}

export interface AdHocFilteringOption {
  AvailabilityStatus?: string;
}

export interface AWS_EMR_InstanceGroupConfig____ScalingConstraints {
  MaxCapacity: number;
  MinCapacity: number;
}

export interface Typography {
  FontFamilies?: Array<Font>;
}

export interface S3Target {
  ConnectionName?: string;
  Path?: string;
  Exclusions?: Array<string>;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____ResourceDataContainer {
  SecretsManagerSecretResourceData?: AWS_Greengrass_ResourceDefinitionVersion____SecretsManagerSecretResourceData;
  SageMakerMachineLearningModelResourceData?: AWS_Greengrass_ResourceDefinitionVersion____SageMakerMachineLearningModelResourceData;
  LocalVolumeResourceData?: AWS_Greengrass_ResourceDefinitionVersion____LocalVolumeResourceData;
  LocalDeviceResourceData?: AWS_Greengrass_ResourceDefinitionVersion____LocalDeviceResourceData;
  S3MachineLearningModelResourceData?: AWS_Greengrass_ResourceDefinitionVersion____S3MachineLearningModelResourceData;
}

export interface AWS_Greengrass_FunctionDefinition____ResourceAccessPolicy {
  ResourceId: string;
  Permission?: string;
}

export interface ParquetSerDe {
  BlockSizeBytes?: number;
  Compression?: string;
  EnableDictionaryCompression?: boolean;
  MaxPaddingBytes?: number;
  PageSizeBytes?: number;
  WriterVersion?: string;
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule____TargetGroupStickinessConfig {
  Enabled?: boolean;
  DurationSeconds?: number;
}

export interface AWS_CloudWatch_Alarm____Dimension {
  Name: string;
  Value: string;
}

export interface AWS_Glue_Partition____SchemaId {
  RegistryName?: string;
  SchemaName?: string;
  SchemaArn?: string;
}

export interface AWS_WAFv2_WebACL____VisibilityConfig {
  SampledRequestsEnabled: boolean;
  CloudWatchMetricsEnabled: boolean;
  MetricName: string;
}

export interface Transition {
  StorageClass: string;
  TransitionDate?: string;
  TransitionInDays?: number;
}

export interface SamplingRuleRecord {
  CreatedAt?: string;
  ModifiedAt?: string;
  SamplingRule?: SamplingRule;
}

export interface AWS_EC2_SpotFleet____InstanceIpv6Address {
  Ipv6Address: string;
}

export interface AWS_Greengrass_ResourceDefinitionVersion____GroupOwnerSetting {
  AutoAddGroupOwner: boolean;
  GroupOwner?: string;
}

export interface CustomDomainConfigType {
  CertificateArn?: string;
}

export interface AWS_ECS_TaskDefinition____HealthCheck {
  Command?: Array<string>;
  Interval?: number;
  Timeout?: number;
  Retries?: number;
  StartPeriod?: number;
}

export interface LambdaExecutionParameters {
  EventSources?: Array<LambdaEventSource>;
  MaxQueueSize?: number;
  MaxInstancesCount?: number;
  MaxIdleTimeInSeconds?: number;
  TimeoutInSeconds?: number;
  StatusTimeoutInSeconds?: number;
  Pinned?: boolean;
  InputPayloadEncodingType?: string;
  ExecArgs?: Array<string>;
  EnvironmentVariables?: Record<string, string>;
  LinuxProcessParams?: LambdaLinuxProcessParams;
}

export interface TargetGroupsConfig {
  TargetGroups: Array<TargetGroup>;
}

export interface AccessLog {
  File?: FileAccessLog;
}

export interface DecodeConfig {
  UnvalidatedJSON?: string;
}

export interface InforNexusConnectorProfileCredentials {
  AccessKeyId: string;
  UserId: string;
  SecretAccessKey: string;
  Datakey: string;
}

export interface ElasticInferenceAccelerator {
  Count?: number;
  Type: string;
}

export interface AWS_Transfer_Server____EndpointDetails {
  AddressAllocationIds?: Array<string>;
  VpcId?: string;
  VpcEndpointId?: string;
  SecurityGroupIds?: Array<string>;
  SubnetIds?: Array<string>;
}

export interface CloudwatchAlarmAction {
  StateValue: string;
  AlarmName: string;
  StateReason: string;
  RoleArn: string;
}

export interface MatchAttributes {
  Sources?: Array<Address>;
  Destinations?: Array<Address>;
  SourcePorts?: Array<AWS_NetworkFirewall_RuleGroup____PortRange>;
  DestinationPorts?: Array<AWS_NetworkFirewall_RuleGroup____PortRange>;
  Protocols?: Array<number>;
  TCPFlags?: Array<TCPFlagField>;
}

export interface VirtualGatewayListenerTlsValidationContextTrust {
  SDS?: VirtualGatewayTlsValidationContextSdsTrust;
  File?: VirtualGatewayTlsValidationContextFileTrust;
}

export interface Cors {
  AllowOrigins?: Array<string>;
  AllowCredentials?: boolean;
  ExposeHeaders?: Array<string>;
  AllowHeaders?: Array<string>;
  MaxAge?: number;
  AllowMethods?: Array<string>;
}

export interface AWS_KinesisAnalytics_Application____InputProcessingConfiguration {
  InputLambdaProcessor?: AWS_KinesisAnalytics_Application____InputLambdaProcessor;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____StoppingCondition {
  MaxRuntimeInSeconds: number;
}

export interface GameProperty {
  Value: string;
  Key: string;
}

export interface AWS_FraudDetector_Detector____Rule {
  RuleId?: string;
  RuleVersion?: string;
  DetectorId?: string;
  Expression?: string;
  Language?: string;
  Outcomes?: Array<Outcome>;
  Arn?: string;
  Description?: string;
  Tags?: Array<Tag>;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface GroupIdentifier {
  GroupId: string;
}

export interface AWS_EMR_Cluster____ScalingRule {
  Action: AWS_EMR_Cluster____ScalingAction;
  Description?: string;
  Name: string;
  Trigger: AWS_EMR_Cluster____ScalingTrigger;
}

export interface VirtualGatewayListenerTlsSdsCertificate {
  SecretName: string;
}

export interface Log {
  LogGroupName?: string;
  LogPath?: string;
  LogType: string;
  Encoding?: string;
  PatternSet?: string;
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition____EndpointInput {
  EndpointName: string;
  LocalPath: string;
  S3DataDistributionType?: string;
  S3InputMode?: string;
  FeaturesAttribute?: string;
  InferenceAttribute?: string;
  ProbabilityAttribute?: string;
}

export interface AWS_AppFlow_Flow____TriggerConfig {
  TriggerType: string;
  TriggerProperties?: ScheduledTriggerProperties;
}

export interface CloudwatchLogsAction {
  LogGroupName: string;
  RoleArn: string;
}

export interface CachingConfig {
  CachingKeys?: Array<string>;
  Ttl?: number;
}

export interface IngestionWaitPolicy {
  WaitForSpiceIngestion?: boolean;
  IngestionWaitTimeInHours?: number;
}

export interface ParameterValue {
  Id: string;
  StringValue: string;
}

export interface AWS_CloudFront_CachePolicy____QueryStringsConfig {
  QueryStringBehavior: string;
  QueryStrings?: Array<string>;
}

export interface AWS_CloudFront_Distribution____Logging {
  Bucket: string;
  IncludeCookies?: boolean;
  Prefix?: string;
}

export interface AdditionalAuthenticationProvider {
  OpenIDConnectConfig?: OpenIDConnectConfig;
  UserPoolConfig?: CognitoUserPoolConfig;
  AuthenticationType: string;
}

export interface RulesConfigurationType {
  Rules: Array<MappingRule>;
}

export interface AWS_ECS_TaskDefinition____LinuxParameters {
  Capabilities?: KernelCapabilities;
  Devices?: Array<AWS_ECS_TaskDefinition____Device>;
  InitProcessEnabled?: boolean;
  MaxSwap?: number;
  SharedMemorySize?: number;
  Swappiness?: number;
  Tmpfs?: Array<AWS_ECS_TaskDefinition____Tmpfs>;
}

export interface AWS_Glue_Job____NotificationProperty {
  NotifyDelayAfter?: number;
}

export interface ExecutionProperty {
  MaxConcurrentRuns?: number;
}

export interface AWS_AppConfig_ConfigurationProfile____Tags {
  Value?: string;
  Key?: string;
}

export interface ContainerProvider {
  Type: string;
  Id: string;
  Info: ContainerInfo;
}

export interface AWS_SageMaker_ModelBiasJobDefinition____MonitoringOutput {
  S3Output: AWS_SageMaker_ModelBiasJobDefinition____S3Output;
}

export interface RuleVariables {
  IPSets?: Record<string, IPSet>;
  PortSets?: Record<string, PortSet>;
}

export interface AWS_AppMesh_VirtualNode____SubjectAlternativeNameMatchers {
  Exact?: Array<string>;
}

export interface SubComponentTypeConfiguration {
  SubComponentType: string;
  SubComponentConfigurationDetails: SubComponentConfigurationDetails;
}

export interface AmplitudeSourceProperties {
  Object: string;
}

export interface AWS_WAFv2_WebACL____IPSetReferenceStatement {
  Arn: string;
  IPSetForwardedIPConfig?: AWS_WAFv2_WebACL____IPSetForwardedIPConfiguration;
}

export interface AWS_AmazonMQ_ConfigurationAssociation____ConfigurationId {
  Revision: number;
  Id: string;
}

export interface JsonConfiguration {}

export interface StorageLensConfiguration {
  Id: string;
  Include?: BucketsAndRegions;
  Exclude?: BucketsAndRegions;
  AwsOrg?: AwsOrg;
  AccountLevel: AccountLevel;
  DataExport?: AWS_S3_StorageLens____DataExport;
  IsEnabled: boolean;
  StorageLensArn?: string;
}

export interface DatadogConnectorProfileProperties {
  InstanceUrl: string;
}

export interface CalculatedColumn {
  ColumnId: string;
  ColumnName: string;
  Expression: string;
}

export interface DeviceConfiguration {
  DeviceOnlyRememberedOnUserPrompt?: boolean;
  ChallengeRequiredOnNewDevice?: boolean;
}

export interface AWS_CloudFront_OriginRequestPolicy____HeadersConfig {
  HeaderBehavior: string;
  Headers?: Array<string>;
}

export interface TracingConfiguration {
  Enabled?: boolean;
}

export interface CastColumnTypeOperation {
  ColumnName: string;
  Format?: string;
  NewColumnType: string;
}

export interface TargetTrackingScalingPolicyConfiguration {
  CustomizedMetricSpecification?: AWS_ApplicationAutoScaling_ScalingPolicy____CustomizedMetricSpecification;
  DisableScaleIn?: boolean;
  PredefinedMetricSpecification?: AWS_ApplicationAutoScaling_ScalingPolicy____PredefinedMetricSpecification;
  ScaleInCooldown?: number;
  ScaleOutCooldown?: number;
  TargetValue: number;
}

export interface AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration {
  BucketARN: string;
  BufferingHints?: BufferingHints;
  CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
  CompressionFormat?: string;
  EncryptionConfiguration?: AWS_KinesisFirehose_DeliveryStream____EncryptionConfiguration;
  ErrorOutputPrefix?: string;
  Prefix?: string;
  RoleARN: string;
}

export interface GenerateSecretString {
  ExcludeUppercase?: boolean;
  RequireEachIncludedType?: boolean;
  IncludeSpace?: boolean;
  ExcludeCharacters?: string;
  GenerateStringKey?: string;
  PasswordLength?: number;
  ExcludePunctuation?: boolean;
  ExcludeLowercase?: boolean;
  SecretStringTemplate?: string;
  ExcludeNumbers?: boolean;
}

export interface AWS_Greengrass_ResourceDefinition____ResourceDataContainer {
  SecretsManagerSecretResourceData?: AWS_Greengrass_ResourceDefinition____SecretsManagerSecretResourceData;
  SageMakerMachineLearningModelResourceData?: AWS_Greengrass_ResourceDefinition____SageMakerMachineLearningModelResourceData;
  LocalVolumeResourceData?: AWS_Greengrass_ResourceDefinition____LocalVolumeResourceData;
  LocalDeviceResourceData?: AWS_Greengrass_ResourceDefinition____LocalDeviceResourceData;
  S3MachineLearningModelResourceData?: AWS_Greengrass_ResourceDefinition____S3MachineLearningModelResourceData;
}

export interface AWS_AutoScaling_AutoScalingGroup____LaunchTemplate {
  LaunchTemplateSpecification: AWS_AutoScaling_AutoScalingGroup____LaunchTemplateSpecification;
  Overrides?: Array<AWS_AutoScaling_AutoScalingGroup____LaunchTemplateOverrides>;
}

export interface ClientAuthentication {
  Sasl?: Sasl;
  Tls?: Tls;
}

export interface AWS_AppSync_FunctionConfiguration____LambdaConflictHandlerConfig {
  LambdaConflictHandlerArn?: string;
}

export interface HealthCheckTag {
  Key: string;
  Value: string;
}

export interface AWS_CodeBuild_Project____EnvironmentVariable {
  Type?: string;
  Value: string;
  Name: string;
}

export interface PosixProfile {
  Uid: number;
  SecondaryGids?: Array<number>;
  Gid: number;
}

export interface PlacementTemplate {
  DeviceTemplates?: any;
  DefaultAttributes?: any;
}

export interface MemberFabricConfiguration {
  AdminUsername: string;
  AdminPassword: string;
}

export interface AWS_WAFv2_RuleGroup____SqliMatchStatement {
  FieldToMatch: AWS_WAFv2_RuleGroup____FieldToMatch;
  TextTransformations: Array<AWS_WAFv2_RuleGroup____TextTransformation>;
}

export interface ProxyConfiguration {
  ContainerName: string;
  ProxyConfigurationProperties?: Array<KeyValuePair>;
  Type?: string;
}

export interface MaxCountRule {
  DeleteSourceFromS3?: boolean;
  Enabled?: boolean;
  MaxCount?: number;
}

export interface ReplicationRuleFilter {
  And?: ReplicationRuleAndOperator;
  Prefix?: string;
  TagFilter?: AWS_S3_Bucket____TagFilter;
}

export interface AWS_ElastiCache_ReplicationGroup____KinesisFirehoseDestinationDetails {
  DeliveryStream?: string;
}

export interface TagProperty {
  Key: string;
  PropagateAtLaunch: boolean;
  Value: string;
}

export interface ActionTypeId {
  Category: string;
  Owner: string;
  Provider: string;
  Version: string;
}

export interface RedshiftDataParameters {
  Database: string;
  DbUser?: string;
  SecretManagerArn?: string;
  Sql: string;
  StatementName?: string;
  WithEvent?: boolean;
}

export interface Eirp {
  Value?: number;
  Units?: string;
}

export interface AWS_Glue_Table____SchemaReference {
  SchemaId?: AWS_Glue_Table____SchemaId;
  SchemaVersionNumber?: number;
  SchameVersionId?: string;
}

export interface AWS_NetworkFirewall_RuleGroup____PublishMetricAction {
  Dimensions: Array<AWS_NetworkFirewall_RuleGroup____Dimension>;
}

export interface AWS_Greengrass_FunctionDefinitionVersion____ResourceAccessPolicy {
  ResourceId: string;
  Permission?: string;
}

export interface EcsParameters {
  Group?: string;
  LaunchType?: string;
  NetworkConfiguration?: AWS_Events_Rule____NetworkConfiguration;
  PlatformVersion?: string;
  TaskCount?: number;
  TaskDefinitionArn: string;
}

export interface AWS_DataBrew_Recipe____DataCatalogInputDefinition {
  CatalogId?: string;
  DatabaseName?: string;
  TableName?: string;
  TempDirectory?: AWS_DataBrew_Recipe____S3Location;
}

export interface Scale {
  Unit?: string;
  Value?: number;
}

export interface AWS_AppMesh_VirtualNode____SubjectAlternativeNames {
  Match: AWS_AppMesh_VirtualNode____SubjectAlternativeNameMatchers;
}

export interface AccountLevel {
  ActivityMetrics?: ActivityMetrics;
  BucketLevel: BucketLevel;
}

export interface FunctionAssociation {
  EventType?: string;
  FunctionARN?: string;
}

export interface AWS_CodeStarNotifications_NotificationRule____Target {
  TargetType?: string;
  TargetAddress?: string;
}

export interface QuotaSettings {
  Limit?: number;
  Offset?: number;
  Period?: string;
}

export interface VirtualNodeGrpcConnectionPool {
  MaxRequests: number;
}

export interface LoggerDefinitionVersion {
  Loggers: Array<AWS_Greengrass_LoggerDefinition____Logger>;
}

export interface Field {
  Key: string;
  RefValue?: string;
  StringValue?: string;
}

export interface AWS_Batch_JobDefinition____Device {
  HostPath?: string;
  Permissions?: Array<string>;
  ContainerPath?: string;
}

export interface AWS_SageMaker_Domain____SharingSettings {
  NotebookOutputOption?: string;
  S3KmsKeyId?: string;
  S3OutputPath?: string;
}

export interface ServerCertificateSummary {
  ServerCertificateArn?: string;
  ServerCertificateStatus?: string;
  ServerCertificateStatusDetail?: string;
}

export interface ResourcesVpcConfig {
  SecurityGroupIds?: Array<string>;
  SubnetIds: Array<string>;
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource____ReferenceDataSource {
  ReferenceSchema: AWS_KinesisAnalytics_ApplicationReferenceDataSource____ReferenceSchema;
  TableName?: string;
  S3ReferenceDataSource?: AWS_KinesisAnalytics_ApplicationReferenceDataSource____S3ReferenceDataSource;
}

export interface TimestreamDimension {
  Name: string;
  Value: string;
}

export interface AWS_DataSync_LocationSMB____MountOptions {
  Version?: string;
}

export interface EnvironmentProperties {
  PropertyGroups?: Array<PropertyGroup>;
}

export interface InputDefinition {
  Attributes: Array<Attribute>;
}

export interface BodyS3Location {
  Etag?: string;
  Bucket?: string;
  Version?: string;
  Key?: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____ReferenceSchema {
  RecordEncoding?: string;
  RecordColumns: Array<AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____RecordColumn>;
  RecordFormat: AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____RecordFormat;
}

export interface MatchRange {
  Start: number;
  End: number;
}

export interface AWS_KinesisAnalytics_Application____InputLambdaProcessor {
  ResourceARN: string;
  RoleARN: string;
}

export interface AWS_EC2_SpotFleet____BlockDeviceMapping {
  DeviceName: string;
  Ebs?: AWS_EC2_SpotFleet____EbsBlockDevice;
  NoDevice?: string;
  VirtualName?: string;
}

export interface FeatureDefinition {
  FeatureName: string;
  FeatureType: string;
}

export interface AWS_ACMPCA_Certificate____KeyUsage {
  DigitalSignature?: boolean;
  NonRepudiation?: boolean;
  KeyEncipherment?: boolean;
  DataEncipherment?: boolean;
  KeyAgreement?: boolean;
  KeyCertSign?: boolean;
  CRLSign?: boolean;
  EncipherOnly?: boolean;
  DecipherOnly?: boolean;
}

export interface AWS_CloudFront_CachePolicy____CookiesConfig {
  CookieBehavior: string;
  Cookies?: Array<string>;
}

export interface AWS_IoTEvents_DetectorModel____Lambda {
  FunctionArn: string;
  Payload?: Payload;
}

export interface StatisticalThreshold {
  Statistic?: string;
}

export interface AWS_WAFRegional_RateBasedRule____Predicate {
  Type: string;
  DataId: string;
  Negated: boolean;
}

export interface AWS_WAFv2_RuleGroup____NotStatement {
  Statement: AWS_WAFv2_RuleGroup____Statement;
}

export type Protocol = string;

export interface AWS_DataBrew_Dataset____S3Location {
  Bucket: string;
  Key?: string;
}

export interface TimestreamTimestamp {
  Value: string;
  Unit: string;
}

export interface S3SourceConfig {
  RoleArn: string;
  TemplatedPathList?: Array<string>;
  HistoricalDataPathList?: Array<string>;
  FileFormatDescriptor: FileFormatDescriptor;
}

export interface AWS_CloudWatch_Alarm____Metric {
  Dimensions?: Array<AWS_CloudWatch_Alarm____Dimension>;
  MetricName?: string;
  Namespace?: string;
}

export interface PredefinedLoadMetricSpecification {
  PredefinedLoadMetricType: string;
  ResourceLabel?: string;
}

export interface AWS_EMR_InstanceFleetConfig____InstanceFleetProvisioningSpecifications {
  OnDemandSpecification?: AWS_EMR_InstanceFleetConfig____OnDemandProvisioningSpecification;
  SpotSpecification?: AWS_EMR_InstanceFleetConfig____SpotProvisioningSpecification;
}

export interface AWS_ElasticLoadBalancing_LoadBalancer____Policies {
  Attributes: Array<any>;
  InstancePorts?: Array<string>;
  LoadBalancerPorts?: Array<string>;
  PolicyName: string;
  PolicyType: string;
}

export interface AWS_Events_Rule____AwsVpcConfiguration {
  AssignPublicIp?: string;
  SecurityGroups?: Array<string>;
  Subnets: Array<string>;
}

export interface RouteSettings {
  LoggingLevel?: string;
  DataTraceEnabled?: boolean;
  ThrottlingBurstLimit?: number;
  DetailedMetricsEnabled?: boolean;
  ThrottlingRateLimit?: number;
}

export interface ElasticIp {
  Ip: string;
  Name?: string;
}

export interface AWS_SageMaker_ModelQualityJobDefinition____MonitoringOutputConfig {
  KmsKeyId?: string;
  MonitoringOutputs: Array<AWS_SageMaker_ModelQualityJobDefinition____MonitoringOutput>;
}

export interface AWS_RDS_DBCluster____DBClusterRole {
  FeatureName?: string;
  RoleArn: string;
}

export interface AWS_KinesisFirehose_DeliveryStream____VpcConfiguration {
  RoleARN: string;
  SubnetIds: Array<string>;
  SecurityGroupIds: Array<string>;
}

export interface AWS_EMR_Cluster____AutoScalingPolicy {
  Constraints: AWS_EMR_Cluster____ScalingConstraints;
  Rules: Array<AWS_EMR_Cluster____ScalingRule>;
}

export interface StreamSpecification {
  StreamViewType: string;
}

export interface SamplingRule {
  Attributes?: Record<string, string>;
  FixedRate?: number;
  Host?: string;
  HTTPMethod?: string;
  Priority?: number;
  ReservoirSize?: number;
  ResourceARN?: string;
  RuleARN?: string;
  RuleName?: string;
  ServiceName?: string;
  ServiceType?: string;
  URLPath?: string;
  Version?: number;
}

export interface AWS_WAFv2_RuleGroup____ForwardedIPConfiguration {
  HeaderName: string;
  FallbackBehavior: string;
}

export interface ExtendedS3DestinationConfiguration {
  BucketARN: string;
  BufferingHints?: BufferingHints;
  CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
  CompressionFormat?: string;
  DataFormatConversionConfiguration?: DataFormatConversionConfiguration;
  EncryptionConfiguration?: AWS_KinesisFirehose_DeliveryStream____EncryptionConfiguration;
  ErrorOutputPrefix?: string;
  Prefix?: string;
  ProcessingConfiguration?: ProcessingConfiguration;
  RoleARN: string;
  S3BackupConfiguration?: AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration;
  S3BackupMode?: string;
}

export interface AWS_WAFv2_RuleGroup____SizeConstraintStatement {
  FieldToMatch: AWS_WAFv2_RuleGroup____FieldToMatch;
  ComparisonOperator: string;
  Size: number;
  TextTransformations: Array<AWS_WAFv2_RuleGroup____TextTransformation>;
}

export interface AWS_ImageBuilder_ImageRecipe____EbsInstanceBlockDeviceSpecification {
  Encrypted?: boolean;
  DeleteOnTermination?: boolean;
  Iops?: number;
  KmsKeyId?: string;
  SnapshotId?: string;
  VolumeSize?: number;
  VolumeType?: string;
}

export interface ElasticsearchConfig {
  AwsRegion: string;
  Endpoint: string;
}

export interface AWS_CloudWatch_AnomalyDetector____Configuration {
  MetricTimeZone?: string;
  ExcludedTimeRanges?: Array<Range>;
}

export interface Tls {
  CertificateAuthorityArnList?: Array<string>;
}

export interface RedshiftDestinationConfiguration {
  CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
  ClusterJDBCURL: string;
  CopyCommand: CopyCommand;
  Password: string;
  ProcessingConfiguration?: ProcessingConfiguration;
  RetryOptions?: RedshiftRetryOptions;
  RoleARN: string;
  S3BackupConfiguration?: AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration;
  S3BackupMode?: string;
  S3Configuration: AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration;
  Username: string;
}

export interface EBSOptions {
  EBSEnabled?: boolean;
  Iops?: number;
  VolumeSize?: number;
  VolumeType?: string;
}

export interface OpenMonitoring {
  Prometheus: Prometheus;
}

export interface HttpEndpointCommonAttribute {
  AttributeName: string;
  AttributeValue: string;
}

export interface AWS_EMR_InstanceFleetConfig____EbsBlockDeviceConfig {
  VolumeSpecification: AWS_EMR_InstanceFleetConfig____VolumeSpecification;
  VolumesPerInstance?: number;
}

export interface AWS_AccessAnalyzer_Analyzer____Filter {
  Contains?: Array<string>;
  Eq?: Array<string>;
  Exists?: boolean;
  Property: string;
  Neq?: Array<string>;
}

export interface DeltaSyncConfig {
  BaseTableTTL: string;
  DeltaSyncTableTTL: string;
  DeltaSyncTableName: string;
}

export interface LogicalTableSource {
  PhysicalTableId?: string;
  JoinInstruction?: JoinInstruction;
}

export interface LaunchTemplateElasticInferenceAccelerator {
  Type?: string;
  Count?: number;
}

export interface SourceDetail {
  EventSource: string;
  MaximumExecutionFrequency?: string;
  MessageType: string;
}

export interface Entry {
  Cidr: string;
  Description?: string;
}

export interface LaunchTemplateTagSpecification {
  ResourceType?: string;
  Tags?: Array<Tag>;
}

export interface SqlServerParameters {
  Port: number;
  Database: string;
  Host: string;
}

export interface Repository {
  PathComponent: string;
  RepositoryUrl: string;
}

export interface AWS_ElasticLoadBalancingV2_Listener____TargetGroupTuple {
  TargetGroupArn?: string;
  Weight?: number;
}

export interface HttpEndpointDestinationConfiguration {
  RoleARN?: string;
  EndpointConfiguration: HttpEndpointConfiguration;
  RequestConfiguration?: HttpEndpointRequestConfiguration;
  BufferingHints?: BufferingHints;
  CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
  ProcessingConfiguration?: ProcessingConfiguration;
  RetryOptions?: RetryOptions;
  S3BackupMode?: string;
  S3Configuration: AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration;
}

export interface TemplateSourceAnalysis {
  DataSetReferences: Array<AWS_QuickSight_Template____DataSetReference>;
  Arn: string;
}

export interface AWS_EMR_Cluster____HadoopJarStepConfig {
  Args?: Array<string>;
  Jar: string;
  MainClass?: string;
  StepProperties?: Array<AWS_EMR_Cluster____KeyValue>;
}

export interface AWS_ECS_Cluster____CapacityProviderStrategyItem {
  CapacityProvider?: string;
  Weight?: number;
  Base?: number;
}

export interface AWS_Greengrass_ConnectorDefinitionVersion____Connector {
  ConnectorArn: string;
  Parameters?: any;
  Id: string;
}

export interface OptionConfiguration {
  DBSecurityGroupMemberships?: Array<string>;
  OptionName: string;
  OptionSettings?: Array<AWS_RDS_OptionGroup____OptionSetting>;
  OptionVersion?: string;
  Port?: number;
  VpcSecurityGroupMemberships?: Array<string>;
}

export interface AWS_OpsWorks_App____Source {
  Password?: string;
  Revision?: string;
  SshKey?: string;
  Type?: string;
  Url?: string;
  Username?: string;
}

export interface PosixUser {
  Uid: string;
  Gid: string;
  SecondaryGids?: Array<string>;
}

export interface Address {
  AddressDefinition: string;
}

export interface EncryptionAtRestOptions {
  Enabled?: boolean;
  KmsKeyId?: string;
}

export interface OrganizationCustomRuleMetadata {
  TagKeyScope?: string;
  TagValueScope?: string;
  Description?: string;
  ResourceIdScope?: string;
  LambdaFunctionArn: string;
  OrganizationConfigRuleTriggerTypes: Array<string>;
  ResourceTypesScope?: Array<string>;
  MaximumExecutionFrequency?: string;
  InputParameters?: string;
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____CSVMappingParameters {
  RecordRowDelimiter: string;
  RecordColumnDelimiter: string;
}

export interface Ec2ConfigurationObject {
  ImageIdOverride?: string;
  ImageType: string;
}

export interface TableIdentifier {
  DatabaseName?: string;
  CatalogId?: string;
  Name?: string;
}

export interface RulesSource {
  RulesString?: string;
  RulesSourceList?: RulesSourceList;
  StatefulRules?: Array<StatefulRule>;
  StatelessRulesAndCustomActions?: StatelessRulesAndCustomActions;
}

export interface VpcInterfaceAttachment {
  VpcInterfaceName?: string;
}

export interface StatefulRule {
  Action: string;
  Header: Header;
  RuleOptions: Array<RuleOption>;
}

export interface UsernameConfiguration {
  CaseSensitive?: boolean;
}

export interface EventType {
  Name?: string;
  Inline?: boolean;
  Tags?: Array<Tag>;
  Description?: string;
  EventVariables?: Array<AWS_FraudDetector_Detector____EventVariable>;
  Labels?: Array<AWS_FraudDetector_Detector____Label>;
  EntityTypes?: Array<AWS_FraudDetector_Detector____EntityType>;
  Arn?: string;
  CreatedTime?: string;
  LastUpdatedTime?: string;
}

export interface ServiceNowConnectorProfileProperties {
  InstanceUrl: string;
}

export interface WebhookAuthConfiguration {
  AllowedIPRange?: string;
  SecretToken?: string;
}

export interface Spend {
  Amount: number;
  Unit: string;
}

export interface ConnectorProfileProperties {
  Datadog?: DatadogConnectorProfileProperties;
  Dynatrace?: DynatraceConnectorProfileProperties;
  InforNexus?: InforNexusConnectorProfileProperties;
  Marketo?: MarketoConnectorProfileProperties;
  Redshift?: RedshiftConnectorProfileProperties;
  Salesforce?: SalesforceConnectorProfileProperties;
  ServiceNow?: ServiceNowConnectorProfileProperties;
  Slack?: SlackConnectorProfileProperties;
  Snowflake?: SnowflakeConnectorProfileProperties;
  Veeva?: VeevaConnectorProfileProperties;
  Zendesk?: ZendeskConnectorProfileProperties;
}

export interface EC2TagSetListObject {
  Ec2TagGroup?: Array<EC2TagFilter>;
}

export interface ScalableTargetAction {
  MaxCapacity?: number;
  MinCapacity?: number;
}

export interface AWS_XRay_Group {
  Type: "AWS::XRay::Group";
  Properties: {
    FilterExpression?: string;
    GroupName?: string;
    InsightsConfiguration?: InsightsConfiguration;
    Tags?: Array<any>;
  };
}

export interface AWS_EC2_RouteTable {
  Type: "AWS::EC2::RouteTable";
  Properties: {
    Tags?: Array<Tag>;
    VpcId: string;
  };
}

export interface AWS_ServiceCatalog_PortfolioShare {
  Type: "AWS::ServiceCatalog::PortfolioShare";
  Properties: {
    AccountId: string;
    AcceptLanguage?: string;
    PortfolioId: string;
    ShareTagOptions?: boolean;
  };
}

export interface AWS_ACMPCA_CertificateAuthority {
  Type: "AWS::ACMPCA::CertificateAuthority";
  Properties: {
    Type: string;
    KeyAlgorithm: string;
    SigningAlgorithm: string;
    Subject: AWS_ACMPCA_CertificateAuthority____Subject;
    RevocationConfiguration?: RevocationConfiguration;
    Tags?: Array<Tag>;
    CsrExtensions?: CsrExtensions;
    KeyStorageSecurityStandard?: string;
  };
}

export interface AWS_GlobalAccelerator_Accelerator {
  Type: "AWS::GlobalAccelerator::Accelerator";
  Properties: {
    Name: string;
    IpAddressType?: string;
    IpAddresses?: Array<string>;
    Enabled?: boolean;
    Tags?: Array<Tag>;
  };
}

export interface AWS_AccessAnalyzer_Analyzer {
  Type: "AWS::AccessAnalyzer::Analyzer";
  Properties: {
    AnalyzerName?: string;
    ArchiveRules?: Array<ArchiveRule>;
    Tags?: Array<Tag>;
    Type: string;
  };
}

export interface AWS_WAF_IPSet {
  Type: "AWS::WAF::IPSet";
  Properties: {
    IPSetDescriptors?: Array<AWS_WAF_IPSet____IPSetDescriptor>;
    Name: string;
  };
}

export interface AWS_IAM_Group {
  Type: "AWS::IAM::Group";
  Properties: {
    GroupName?: string;
    ManagedPolicyArns?: Array<string>;
    Path?: string;
    Policies?: Array<AWS_IAM_Group____Policy>;
  };
}

export interface AWS_WAFRegional_RateBasedRule {
  Type: "AWS::WAFRegional::RateBasedRule";
  Properties: {
    MetricName: string;
    RateLimit: number;
    MatchPredicates?: Array<AWS_WAFRegional_RateBasedRule____Predicate>;
    RateKey: string;
    Name: string;
  };
}

export interface AWS_Backup_BackupPlan {
  Type: "AWS::Backup::BackupPlan";
  Properties: {
    BackupPlan: BackupPlanResourceType;
    BackupPlanTags?: Record<string, string>;
  };
}

export interface AWS_Route53Resolver_ResolverQueryLoggingConfig {
  Type: "AWS::Route53Resolver::ResolverQueryLoggingConfig";
  Properties: {
    Name?: string;
    DestinationArn?: string;
  };
}

export interface AWS_EC2_VPCPeeringConnection {
  Type: "AWS::EC2::VPCPeeringConnection";
  Properties: {
    PeerOwnerId?: string;
    PeerRegion?: string;
    PeerRoleArn?: string;
    PeerVpcId: string;
    Tags?: Array<Tag>;
    VpcId: string;
  };
}

export interface AWS_Elasticsearch_Domain {
  Type: "AWS::Elasticsearch::Domain";
  Properties: {
    AccessPolicies?: any;
    AdvancedOptions?: Record<string, string>;
    AdvancedSecurityOptions?: AdvancedSecurityOptionsInput;
    CognitoOptions?: CognitoOptions;
    DomainEndpointOptions?: DomainEndpointOptions;
    DomainName?: string;
    EBSOptions?: EBSOptions;
    ElasticsearchClusterConfig?: ElasticsearchClusterConfig;
    ElasticsearchVersion?: string;
    EncryptionAtRestOptions?: EncryptionAtRestOptions;
    LogPublishingOptions?: Record<string, LogPublishingOption>;
    NodeToNodeEncryptionOptions?: NodeToNodeEncryptionOptions;
    SnapshotOptions?: SnapshotOptions;
    Tags?: Array<Tag>;
    VPCOptions?: VPCOptions;
  };
}

export interface AWS_FraudDetector_EntityType {
  Type: "AWS::FraudDetector::EntityType";
  Properties: {
    Name: string;
    Tags?: Array<Tag>;
    Description?: string;
  };
}

export interface AWS_EMR_InstanceFleetConfig {
  Type: "AWS::EMR::InstanceFleetConfig";
  Properties: {
    ClusterId: string;
    InstanceFleetType: string;
    InstanceTypeConfigs?: Array<AWS_EMR_InstanceFleetConfig____InstanceTypeConfig>;
    LaunchSpecifications?: AWS_EMR_InstanceFleetConfig____InstanceFleetProvisioningSpecifications;
    Name?: string;
    TargetOnDemandCapacity?: number;
    TargetSpotCapacity?: number;
  };
}

export interface AWS_WorkSpaces_Workspace {
  Type: "AWS::WorkSpaces::Workspace";
  Properties: {
    BundleId: string;
    DirectoryId: string;
    RootVolumeEncryptionEnabled?: boolean;
    Tags?: Array<Tag>;
    UserName: string;
    UserVolumeEncryptionEnabled?: boolean;
    VolumeEncryptionKey?: string;
    WorkspaceProperties?: WorkspaceProperties;
  };
}

export interface AWS_LookoutMetrics_Alert {
  Type: "AWS::LookoutMetrics::Alert";
  Properties: {
    AlertName?: string;
    AlertDescription?: string;
    AnomalyDetectorArn: string;
    AlertSensitivityThreshold: number;
    Action: any;
  };
}

export interface AWS_WAFRegional_SqlInjectionMatchSet {
  Type: "AWS::WAFRegional::SqlInjectionMatchSet";
  Properties: {
    SqlInjectionMatchTuples?: Array<AWS_WAFRegional_SqlInjectionMatchSet____SqlInjectionMatchTuple>;
    Name: string;
  };
}

export interface AWS_ApiGatewayV2_Route {
  Type: "AWS::ApiGatewayV2::Route";
  Properties: {
    Target?: string;
    RouteResponseSelectionExpression?: string;
    AuthorizerId?: string;
    RequestModels?: any;
    OperationName?: string;
    AuthorizationScopes?: Array<string>;
    ApiKeyRequired?: boolean;
    RouteKey: string;
    AuthorizationType?: string;
    ModelSelectionExpression?: string;
    ApiId: string;
    RequestParameters?: any;
  };
}

export interface AWS_SageMaker_Workteam {
  Type: "AWS::SageMaker::Workteam";
  Properties: {
    Description?: string;
    NotificationConfiguration?: AWS_SageMaker_Workteam____NotificationConfiguration;
    WorkteamName?: string;
    MemberDefinitions?: Array<MemberDefinition>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Kinesis_Stream {
  Type: "AWS::Kinesis::Stream";
  Properties: {
    Name?: string;
    RetentionPeriodHours?: number;
    ShardCount: number;
    StreamEncryption?: StreamEncryption;
    Tags?: Array<Tag>;
  };
}

export interface AWS_RAM_ResourceShare {
  Type: "AWS::RAM::ResourceShare";
  Properties: {
    Principals?: Array<string>;
    AllowExternalPrincipals?: boolean;
    ResourceArns?: Array<string>;
    Tags?: Array<Tag>;
    Name: string;
  };
}

export interface AWS_AutoScaling_LaunchConfiguration {
  Type: "AWS::AutoScaling::LaunchConfiguration";
  Properties: {
    AssociatePublicIpAddress?: boolean;
    BlockDeviceMappings?: Array<AWS_AutoScaling_LaunchConfiguration____BlockDeviceMapping>;
    ClassicLinkVPCId?: string;
    ClassicLinkVPCSecurityGroups?: Array<string>;
    EbsOptimized?: boolean;
    IamInstanceProfile?: string;
    ImageId: string;
    InstanceId?: string;
    InstanceMonitoring?: boolean;
    InstanceType: string;
    KernelId?: string;
    KeyName?: string;
    LaunchConfigurationName?: string;
    MetadataOptions?: AWS_AutoScaling_LaunchConfiguration____MetadataOptions;
    PlacementTenancy?: string;
    RamDiskId?: string;
    SecurityGroups?: Array<string>;
    SpotPrice?: string;
    UserData?: string;
  };
}

export interface AWS_SQS_Queue {
  Type: "AWS::SQS::Queue";
  Properties: {
    ContentBasedDeduplication?: boolean;
    DelaySeconds?: number;
    FifoQueue?: boolean;
    KmsDataKeyReusePeriodSeconds?: number;
    KmsMasterKeyId?: string;
    MaximumMessageSize?: number;
    MessageRetentionPeriod?: number;
    QueueName?: string;
    ReceiveMessageWaitTimeSeconds?: number;
    RedrivePolicy?: any;
    Tags?: Array<Tag>;
    VisibilityTimeout?: number;
  };
}

export interface AWS_EC2_TransitGateway {
  Type: "AWS::EC2::TransitGateway";
  Properties: {
    DefaultRouteTablePropagation?: string;
    Description?: string;
    AutoAcceptSharedAttachments?: string;
    DefaultRouteTableAssociation?: string;
    VpnEcmpSupport?: string;
    DnsSupport?: string;
    MulticastSupport?: string;
    AmazonSideAsn?: number;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SageMaker_ImageVersion {
  Type: "AWS::SageMaker::ImageVersion";
  Properties: {
    ImageName: string;
    BaseImage: string;
  };
}

export interface AWS_EC2_CapacityReservation {
  Type: "AWS::EC2::CapacityReservation";
  Properties: {
    Tenancy?: string;
    EndDateType?: string;
    InstanceCount: number;
    TagSpecifications?: Array<AWS_EC2_CapacityReservation____TagSpecification>;
    AvailabilityZone: string;
    InstancePlatform: string;
    InstanceType: string;
    EphemeralStorage?: boolean;
    InstanceMatchCriteria?: string;
    EndDate?: string;
    EbsOptimized?: boolean;
  };
}

export interface AWS_AppSync_Resolver {
  Type: "AWS::AppSync::Resolver";
  Properties: {
    ResponseMappingTemplateS3Location?: string;
    TypeName: string;
    PipelineConfig?: PipelineConfig;
    DataSourceName?: string;
    RequestMappingTemplate?: string;
    ResponseMappingTemplate?: string;
    Kind?: string;
    CachingConfig?: CachingConfig;
    SyncConfig?: AWS_AppSync_Resolver____SyncConfig;
    RequestMappingTemplateS3Location?: string;
    ApiId: string;
    FieldName: string;
  };
}

export interface AWS_DataSync_LocationNFS {
  Type: "AWS::DataSync::LocationNFS";
  Properties: {
    MountOptions?: AWS_DataSync_LocationNFS____MountOptions;
    OnPremConfig: OnPremConfig;
    ServerHostname: string;
    Subdirectory: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_VPCEndpointServicePermissions {
  Type: "AWS::EC2::VPCEndpointServicePermissions";
  Properties: {
    AllowedPrincipals?: Array<string>;
    ServiceId: string;
  };
}

export interface AWS_Route53_RecordSet {
  Type: "AWS::Route53::RecordSet";
  Properties: {
    AliasTarget?: AWS_Route53_RecordSet____AliasTarget;
    Comment?: string;
    Failover?: string;
    GeoLocation?: AWS_Route53_RecordSet____GeoLocation;
    HealthCheckId?: string;
    HostedZoneId?: string;
    HostedZoneName?: string;
    MultiValueAnswer?: boolean;
    Name: string;
    Region?: string;
    ResourceRecords?: Array<string>;
    SetIdentifier?: string;
    TTL?: string;
    Type: string;
    Weight?: number;
  };
}

export interface AWS_WAF_SizeConstraintSet {
  Type: "AWS::WAF::SizeConstraintSet";
  Properties: {
    Name: string;
    SizeConstraints: Array<AWS_WAF_SizeConstraintSet____SizeConstraint>;
  };
}

export interface AWS_ManagedBlockchain_Member {
  Type: "AWS::ManagedBlockchain::Member";
  Properties: {
    MemberConfiguration: MemberConfiguration;
    NetworkConfiguration?: AWS_ManagedBlockchain_Member____NetworkConfiguration;
    NetworkId?: string;
    InvitationId?: string;
  };
}

export interface AWS_CloudWatch_Dashboard {
  Type: "AWS::CloudWatch::Dashboard";
  Properties: {
    DashboardName?: string;
    DashboardBody: string;
  };
}

export interface AWS_IAM_Policy {
  Type: "AWS::IAM::Policy";
  Properties: {
    Groups?: Array<string>;
    PolicyDocument: any;
    PolicyName: string;
    Roles?: Array<string>;
    Users?: Array<string>;
  };
}

export interface AWS_ServiceCatalog_ServiceActionAssociation {
  Type: "AWS::ServiceCatalog::ServiceActionAssociation";
  Properties: {
    ProductId: string;
    ProvisioningArtifactId: string;
    ServiceActionId: string;
  };
}

export interface AWS_ECS_Cluster {
  Type: "AWS::ECS::Cluster";
  Properties: {
    Tags?: Array<Tag>;
    ClusterName?: string;
    ClusterSettings?: Array<ClusterSettings>;
    Configuration?: ClusterConfiguration;
    CapacityProviders?: Array<string>;
    DefaultCapacityProviderStrategy?: Array<AWS_ECS_Cluster____CapacityProviderStrategyItem>;
  };
}

export interface AWS_SageMaker_FeatureGroup {
  Type: "AWS::SageMaker::FeatureGroup";
  Properties: {
    FeatureGroupName: string;
    RecordIdentifierFeatureName: string;
    EventTimeFeatureName: string;
    FeatureDefinitions: Array<FeatureDefinition>;
    OnlineStoreConfig?: any;
    OfflineStoreConfig?: any;
    RoleArn?: string;
    Description?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_NetworkManager_Link {
  Type: "AWS::NetworkManager::Link";
  Properties: {
    GlobalNetworkId: string;
    SiteId: string;
    Bandwidth: Bandwidth;
    Provider?: string;
    Description?: string;
    Tags?: Array<Tag>;
    Type?: string;
  };
}

export interface AWS_StepFunctions_Activity {
  Type: "AWS::StepFunctions::Activity";
  Properties: {
    Tags?: Array<AWS_StepFunctions_Activity____TagsEntry>;
    Name: string;
  };
}

export interface AWS_KinesisAnalytics_ApplicationOutput {
  Type: "AWS::KinesisAnalytics::ApplicationOutput";
  Properties: {
    ApplicationName: string;
    Output: AWS_KinesisAnalytics_ApplicationOutput____Output;
  };
}

export interface AWS_CodeStarConnections_Connection {
  Type: "AWS::CodeStarConnections::Connection";
  Properties: {
    ConnectionName: string;
    ProviderType?: string;
    HostArn?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CloudFront_KeyGroup {
  Type: "AWS::CloudFront::KeyGroup";
  Properties: {
    KeyGroupConfig: KeyGroupConfig;
  };
}

export interface AWS_CloudFormation_StackSet {
  Type: "AWS::CloudFormation::StackSet";
  Properties: {
    StackSetName: string;
    AdministrationRoleARN?: string;
    AutoDeployment?: AutoDeployment;
    Capabilities?: Array<string>;
    Description?: string;
    ExecutionRoleName?: string;
    OperationPreferences?: OperationPreferences;
    StackInstancesGroup?: Array<StackInstances>;
    Parameters?: Array<AWS_CloudFormation_StackSet____Parameter>;
    PermissionModel: string;
    Tags?: Array<Tag>;
    TemplateBody?: string;
    TemplateURL?: string;
  };
}

export interface AWS_Cognito_UserPoolRiskConfigurationAttachment {
  Type: "AWS::Cognito::UserPoolRiskConfigurationAttachment";
  Properties: {
    CompromisedCredentialsRiskConfiguration?: CompromisedCredentialsRiskConfigurationType;
    UserPoolId: string;
    ClientId: string;
    AccountTakeoverRiskConfiguration?: AccountTakeoverRiskConfigurationType;
    RiskExceptionConfiguration?: RiskExceptionConfigurationType;
  };
}

export interface AWS_Glue_SchemaVersion {
  Type: "AWS::Glue::SchemaVersion";
  Properties: {
    Schema: Schema;
    SchemaDefinition: string;
  };
}

export interface AWS_EC2_TransitGatewayRouteTableAssociation {
  Type: "AWS::EC2::TransitGatewayRouteTableAssociation";
  Properties: {
    TransitGatewayRouteTableId: string;
    TransitGatewayAttachmentId: string;
  };
}

export interface AWS_EC2_Volume {
  Type: "AWS::EC2::Volume";
  Properties: {
    AutoEnableIO?: boolean;
    AvailabilityZone: string;
    Encrypted?: boolean;
    Iops?: number;
    KmsKeyId?: string;
    MultiAttachEnabled?: boolean;
    OutpostArn?: string;
    Size?: number;
    SnapshotId?: string;
    Tags?: Array<Tag>;
    Throughput?: number;
    VolumeType?: string;
  };
}

export interface AWS_AppSync_GraphQLSchema {
  Type: "AWS::AppSync::GraphQLSchema";
  Properties: {
    Definition?: string;
    DefinitionS3Location?: string;
    ApiId: string;
  };
}

export interface AWS_GroundStation_Config {
  Type: "AWS::GroundStation::Config";
  Properties: {
    Name: string;
    Tags?: Array<Tag>;
    ConfigData: ConfigData;
  };
}

export interface AWS_IAM_ServiceLinkedRole {
  Type: "AWS::IAM::ServiceLinkedRole";
  Properties: {
    CustomSuffix?: string;
    Description?: string;
    AWSServiceName: string;
  };
}

export interface AWS_Greengrass_ConnectorDefinitionVersion {
  Type: "AWS::Greengrass::ConnectorDefinitionVersion";
  Properties: {
    Connectors: Array<AWS_Greengrass_ConnectorDefinitionVersion____Connector>;
    ConnectorDefinitionId: string;
  };
}

export interface AWS_ServiceCatalog_ResourceUpdateConstraint {
  Type: "AWS::ServiceCatalog::ResourceUpdateConstraint";
  Properties: {
    Description?: string;
    AcceptLanguage?: string;
    TagUpdateOnProvisionedProduct: string;
    PortfolioId: string;
    ProductId: string;
  };
}

export interface AWS_AppSync_GraphQLApi {
  Type: "AWS::AppSync::GraphQLApi";
  Properties: {
    OpenIDConnectConfig?: OpenIDConnectConfig;
    XrayEnabled?: boolean;
    UserPoolConfig?: UserPoolConfig;
    Tags?: AWS_AppSync_GraphQLApi____Tags;
    Name: string;
    AuthenticationType: string;
    LogConfig?: LogConfig;
    AdditionalAuthenticationProviders?: AdditionalAuthenticationProviders;
  };
}

export interface AWS_CloudFront_StreamingDistribution {
  Type: "AWS::CloudFront::StreamingDistribution";
  Properties: {
    StreamingDistributionConfig: StreamingDistributionConfig;
    Tags: Array<Tag>;
  };
}

export interface AWS_SageMaker_DataQualityJobDefinition {
  Type: "AWS::SageMaker::DataQualityJobDefinition";
  Properties: {
    JobDefinitionName?: string;
    DataQualityBaselineConfig?: DataQualityBaselineConfig;
    DataQualityAppSpecification: DataQualityAppSpecification;
    DataQualityJobInput: DataQualityJobInput;
    DataQualityJobOutputConfig: AWS_SageMaker_DataQualityJobDefinition____MonitoringOutputConfig;
    JobResources: AWS_SageMaker_DataQualityJobDefinition____MonitoringResources;
    NetworkConfig?: AWS_SageMaker_DataQualityJobDefinition____NetworkConfig;
    RoleArn: string;
    StoppingCondition?: AWS_SageMaker_DataQualityJobDefinition____StoppingCondition;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Cognito_UserPoolIdentityProvider {
  Type: "AWS::Cognito::UserPoolIdentityProvider";
  Properties: {
    ProviderName: string;
    UserPoolId: string;
    AttributeMapping?: any;
    ProviderDetails?: any;
    ProviderType: string;
    IdpIdentifiers?: Array<string>;
  };
}

export interface AWS_ACMPCA_CertificateAuthorityActivation {
  Type: "AWS::ACMPCA::CertificateAuthorityActivation";
  Properties: {
    CertificateAuthorityArn: string;
    Certificate: string;
    CertificateChain?: string;
    Status?: string;
  };
}

export interface AWS_GuardDuty_Filter {
  Type: "AWS::GuardDuty::Filter";
  Properties: {
    Action: string;
    Description: string;
    DetectorId: string;
    FindingCriteria: AWS_GuardDuty_Filter____FindingCriteria;
    Rank: number;
    Name: string;
  };
}

export interface AWS_Budgets_BudgetsAction {
  Type: "AWS::Budgets::BudgetsAction";
  Properties: {
    BudgetName: string;
    NotificationType: string;
    ActionType: string;
    ActionThreshold: ActionThreshold;
    ExecutionRoleArn: string;
    ApprovalModel?: string;
    Subscribers?: Array<AWS_Budgets_BudgetsAction____Subscriber>;
    Definition: AWS_Budgets_BudgetsAction____Definition;
  };
}

export interface AWS_LakeFormation_Resource {
  Type: "AWS::LakeFormation::Resource";
  Properties: {
    ResourceArn: string;
    UseServiceLinkedRole: boolean;
    RoleArn?: string;
  };
}

export interface AWS_S3_AccessPoint {
  Type: "AWS::S3::AccessPoint";
  Properties: {
    Name?: string;
    Bucket: string;
    VpcConfiguration?: AWS_S3_AccessPoint____VpcConfiguration;
    PublicAccessBlockConfiguration?: AWS_S3_AccessPoint____PublicAccessBlockConfiguration;
    Policy?: any;
  };
}

export interface AWS_SNS_Subscription {
  Type: "AWS::SNS::Subscription";
  Properties: {
    DeliveryPolicy?: any;
    Endpoint?: string;
    FilterPolicy?: any;
    Protocol: string;
    RawMessageDelivery?: boolean;
    RedrivePolicy?: any;
    Region?: string;
    SubscriptionRoleArn?: string;
    TopicArn: string;
  };
}

export interface AWS_EFS_MountTarget {
  Type: "AWS::EFS::MountTarget";
  Properties: {
    FileSystemId: string;
    IpAddress?: string;
    SecurityGroups: Array<string>;
    SubnetId: string;
  };
}

export interface AWS_Glue_DataCatalogEncryptionSettings {
  Type: "AWS::Glue::DataCatalogEncryptionSettings";
  Properties: {
    DataCatalogEncryptionSettings: DataCatalogEncryptionSettings;
    CatalogId: string;
  };
}

export interface AWS_SNS_Topic {
  Type: "AWS::SNS::Topic";
  Properties: {
    ContentBasedDeduplication?: boolean;
    DisplayName?: string;
    FifoTopic?: boolean;
    KmsMasterKeyId?: string;
    Subscription?: Array<AWS_SNS_Topic____Subscription>;
    Tags?: Array<Tag>;
    TopicName?: string;
  };
}

export interface AWS_ServiceCatalog_TagOption {
  Type: "AWS::ServiceCatalog::TagOption";
  Properties: {
    Active?: boolean;
    Value: string;
    Key: string;
  };
}

export interface AWS_SageMaker_NotebookInstanceLifecycleConfig {
  Type: "AWS::SageMaker::NotebookInstanceLifecycleConfig";
  Properties: {
    OnStart?: Array<NotebookInstanceLifecycleHook>;
    NotebookInstanceLifecycleConfigName?: string;
    OnCreate?: Array<NotebookInstanceLifecycleHook>;
  };
}

export interface AWS_MediaConnect_FlowSource {
  Type: "AWS::MediaConnect::FlowSource";
  Properties: {
    FlowArn?: string;
    Decryption?: AWS_MediaConnect_FlowSource____Encryption;
    Description: string;
    EntitlementArn?: string;
    IngestPort?: number;
    MaxBitrate?: number;
    MaxLatency?: number;
    Name: string;
    Protocol?: string;
    StreamId?: string;
    VpcInterfaceName?: string;
    WhitelistCidr?: string;
  };
}

export interface AWS_Cognito_UserPoolGroup {
  Type: "AWS::Cognito::UserPoolGroup";
  Properties: {
    GroupName?: string;
    Description?: string;
    UserPoolId: string;
    Precedence?: number;
    RoleArn?: string;
  };
}

export interface AWS_ApiGateway_Deployment {
  Type: "AWS::ApiGateway::Deployment";
  Properties: {
    DeploymentCanarySettings?: DeploymentCanarySettings;
    Description?: string;
    RestApiId: string;
    StageDescription?: StageDescription;
    StageName?: string;
  };
}

export interface AWS_QuickSight_Dashboard {
  Type: "AWS::QuickSight::Dashboard";
  Properties: {
    AwsAccountId: string;
    DashboardId: string;
    DashboardPublishOptions?: DashboardPublishOptions;
    Name?: string;
    Parameters?: AWS_QuickSight_Dashboard____Parameters;
    Permissions?: Array<AWS_QuickSight_Dashboard____ResourcePermission>;
    SourceEntity?: DashboardSourceEntity;
    Tags?: Array<Tag>;
    ThemeArn?: string;
    VersionDescription?: string;
  };
}

export interface AWS_LakeFormation_Permissions {
  Type: "AWS::LakeFormation::Permissions";
  Properties: {
    DataLakePrincipal: AWS_LakeFormation_Permissions____DataLakePrincipal;
    Resource: Resource;
    Permissions?: Array<string>;
    PermissionsWithGrantOption?: Array<string>;
  };
}

export interface AWS_KMS_Key {
  Type: "AWS::KMS::Key";
  Properties: {
    Description?: string;
    Enabled?: boolean;
    EnableKeyRotation?: boolean;
    KeyPolicy: any;
    KeyUsage?: string;
    KeySpec?: string;
    PendingWindowInDays?: number;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Redshift_Cluster {
  Type: "AWS::Redshift::Cluster";
  Properties: {
    AllowVersionUpgrade?: boolean;
    AutomatedSnapshotRetentionPeriod?: number;
    AvailabilityZone?: string;
    ClusterIdentifier?: string;
    ClusterParameterGroupName?: string;
    ClusterSecurityGroups?: Array<string>;
    ClusterSubnetGroupName?: string;
    ClusterType: string;
    ClusterVersion?: string;
    DBName: string;
    ElasticIp?: string;
    Encrypted?: boolean;
    HsmClientCertificateIdentifier?: string;
    HsmConfigurationIdentifier?: string;
    IamRoles?: Array<string>;
    KmsKeyId?: string;
    LoggingProperties?: LoggingProperties;
    MasterUserPassword: string;
    MasterUsername: string;
    NodeType: string;
    NumberOfNodes?: number;
    OwnerAccount?: string;
    Port?: number;
    PreferredMaintenanceWindow?: string;
    PubliclyAccessible?: boolean;
    SnapshotClusterIdentifier?: string;
    SnapshotIdentifier?: string;
    Tags?: Array<Tag>;
    VpcSecurityGroupIds?: Array<string>;
  };
}

export interface AWS_ApplicationInsights_Application {
  Type: "AWS::ApplicationInsights::Application";
  Properties: {
    ResourceGroupName: string;
    CWEMonitorEnabled?: boolean;
    OpsCenterEnabled?: boolean;
    OpsItemSNSTopicArn?: string;
    Tags?: Array<Tag>;
    CustomComponents?: Array<CustomComponent>;
    LogPatternSets?: Array<LogPatternSet>;
    AutoConfigurationEnabled?: boolean;
    ComponentMonitoringSettings?: Array<ComponentMonitoringSetting>;
  };
}

export interface AWS_OpsWorks_App {
  Type: "AWS::OpsWorks::App";
  Properties: {
    AppSource?: AWS_OpsWorks_App____Source;
    Attributes?: Record<string, string>;
    DataSources?: Array<DataSource>;
    Description?: string;
    Domains?: Array<string>;
    EnableSsl?: boolean;
    Environment?: Array<AWS_OpsWorks_App____EnvironmentVariable>;
    Name: string;
    Shortname?: string;
    SslConfiguration?: SslConfiguration;
    StackId: string;
    Type: string;
  };
}

export interface AWS_SageMaker_MonitoringSchedule {
  Type: "AWS::SageMaker::MonitoringSchedule";
  Properties: {
    MonitoringScheduleName: string;
    MonitoringScheduleConfig: MonitoringScheduleConfig;
    Tags?: Array<Tag>;
    EndpointName?: string;
    FailureReason?: string;
    LastMonitoringExecutionSummary?: MonitoringExecutionSummary;
    MonitoringScheduleStatus?: string;
  };
}

export interface AWS_EKS_Nodegroup {
  Type: "AWS::EKS::Nodegroup";
  Properties: {
    ScalingConfig?: ScalingConfig;
    Labels?: any;
    Taints?: Array<Taint>;
    ReleaseVersion?: string;
    CapacityType?: string;
    NodegroupName?: string;
    Subnets: Array<string>;
    NodeRole: string;
    AmiType?: string;
    ForceUpdateEnabled?: boolean;
    Version?: string;
    LaunchTemplate?: AWS_EKS_Nodegroup____LaunchTemplateSpecification;
    RemoteAccess?: RemoteAccess;
    DiskSize?: number;
    ClusterName: string;
    InstanceTypes?: Array<string>;
    Tags?: any;
  };
}

export interface AWS_AppMesh_Route {
  Type: "AWS::AppMesh::Route";
  Properties: {
    MeshName: string;
    VirtualRouterName: string;
    MeshOwner?: string;
    RouteName?: string;
    Spec: RouteSpec;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Lambda_EventSourceMapping {
  Type: "AWS::Lambda::EventSourceMapping";
  Properties: {
    BatchSize?: number;
    BisectBatchOnFunctionError?: boolean;
    DestinationConfig?: AWS_Lambda_EventSourceMapping____DestinationConfig;
    Enabled?: boolean;
    EventSourceArn?: string;
    FunctionName: string;
    MaximumBatchingWindowInSeconds?: number;
    MaximumRecordAgeInSeconds?: number;
    MaximumRetryAttempts?: number;
    ParallelizationFactor?: number;
    StartingPosition?: string;
    Topics?: Array<string>;
    Queues?: Array<string>;
    SourceAccessConfigurations?: Array<SourceAccessConfiguration>;
    PartialBatchResponse?: boolean;
    TumblingWindowInSeconds?: number;
    FunctionResponseTypes?: Array<string>;
    SelfManagedEventSource?: SelfManagedEventSource;
  };
}

export interface AWS_AppConfig_Deployment {
  Type: "AWS::AppConfig::Deployment";
  Properties: {
    DeploymentStrategyId: string;
    ConfigurationProfileId: string;
    EnvironmentId: string;
    Description?: string;
    ConfigurationVersion: string;
    ApplicationId: string;
    Tags?: Array<AWS_AppConfig_Deployment____Tags>;
  };
}

export interface AWS_CE_CostCategory {
  Type: "AWS::CE::CostCategory";
  Properties: {
    Name: string;
    RuleVersion: string;
    Rules: string;
    DefaultValue?: string;
  };
}

export interface AWS_ApiGateway_Authorizer {
  Type: "AWS::ApiGateway::Authorizer";
  Properties: {
    AuthType?: string;
    AuthorizerCredentials?: string;
    AuthorizerResultTtlInSeconds?: number;
    AuthorizerUri?: string;
    IdentitySource?: string;
    IdentityValidationExpression?: string;
    Name?: string;
    ProviderARNs?: Array<string>;
    RestApiId: string;
    Type: string;
  };
}

export interface AWS_EC2_EIP {
  Type: "AWS::EC2::EIP";
  Properties: {
    Domain?: string;
    InstanceId?: string;
    PublicIpv4Pool?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_LocalGatewayRoute {
  Type: "AWS::EC2::LocalGatewayRoute";
  Properties: {
    DestinationCidrBlock: string;
    LocalGatewayRouteTableId: string;
    LocalGatewayVirtualInterfaceGroupId: string;
  };
}

export interface AWS_IoT1Click_Project {
  Type: "AWS::IoT1Click::Project";
  Properties: {
    Description?: string;
    PlacementTemplate: PlacementTemplate;
    ProjectName?: string;
  };
}

export interface AWS_MediaConvert_Queue {
  Type: "AWS::MediaConvert::Queue";
  Properties: {
    Status?: string;
    Description?: string;
    PricingPlan?: string;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_IoT_CustomMetric {
  Type: "AWS::IoT::CustomMetric";
  Properties: {
    MetricName?: string;
    DisplayName?: string;
    MetricType: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ApiGateway_DomainName {
  Type: "AWS::ApiGateway::DomainName";
  Properties: {
    DomainName?: string;
    EndpointConfiguration?: AWS_ApiGateway_DomainName____EndpointConfiguration;
    MutualTlsAuthentication?: AWS_ApiGateway_DomainName____MutualTlsAuthentication;
    CertificateArn?: string;
    RegionalCertificateArn?: string;
    SecurityPolicy?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_QLDB_Stream {
  Type: "AWS::QLDB::Stream";
  Properties: {
    LedgerName: string;
    StreamName: string;
    RoleArn: string;
    InclusiveStartTime: string;
    ExclusiveEndTime?: string;
    KinesisConfiguration: KinesisConfiguration;
    Tags?: Array<Tag>;
  };
}

export interface AWS_WAFRegional_GeoMatchSet {
  Type: "AWS::WAFRegional::GeoMatchSet";
  Properties: {
    GeoMatchConstraints?: Array<GeoMatchConstraint>;
    Name: string;
  };
}

export interface AWS_WAFv2_RegexPatternSet {
  Type: "AWS::WAFv2::RegexPatternSet";
  Properties: {
    Description?: string;
    Name?: string;
    RegularExpressionList: Array<string>;
    Scope: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Batch_JobDefinition {
  Type: "AWS::Batch::JobDefinition";
  Properties: {
    Type: string;
    Parameters?: any;
    NodeProperties?: NodeProperties;
    Timeout?: Timeout;
    ContainerProperties?: ContainerProperties;
    JobDefinitionName?: string;
    PropagateTags?: boolean;
    PlatformCapabilities?: Array<string>;
    RetryStrategy?: RetryStrategy;
    Tags?: any;
  };
}

export interface AWS_DataBrew_Dataset {
  Type: "AWS::DataBrew::Dataset";
  Properties: {
    Name: string;
    Format?: string;
    FormatOptions?: FormatOptions;
    Input: AWS_DataBrew_Dataset____Input;
    PathOptions?: PathOptions;
    Tags?: Array<Tag>;
  };
}

export interface AWS_GameLift_Fleet {
  Type: "AWS::GameLift::Fleet";
  Properties: {
    CertificateConfiguration?: CertificateConfiguration;
    Description?: string;
    DesiredEC2Instances?: number;
    EC2InboundPermissions?: Array<IpPermission>;
    EC2InstanceType?: string;
    FleetType?: string;
    InstanceRoleARN?: string;
    Locations?: Array<LocationConfiguration>;
    MaxSize?: number;
    MetricGroups?: Array<string>;
    MinSize?: number;
    Name?: string;
    NewGameSessionProtectionPolicy?: string;
    PeerVpcAwsAccountId?: string;
    PeerVpcId?: string;
    ResourceCreationLimitPolicy?: ResourceCreationLimitPolicy;
    BuildId?: string;
    ScriptId?: string;
    RuntimeConfiguration?: RuntimeConfiguration;
  };
}

export interface AWS_NetworkManager_CustomerGatewayAssociation {
  Type: "AWS::NetworkManager::CustomerGatewayAssociation";
  Properties: {
    GlobalNetworkId: string;
    CustomerGatewayArn: string;
    DeviceId: string;
    LinkId?: string;
  };
}

export interface AWS_Lambda_LayerVersion {
  Type: "AWS::Lambda::LayerVersion";
  Properties: {
    CompatibleRuntimes?: Array<string>;
    LicenseInfo?: string;
    Description?: string;
    LayerName?: string;
    Content: Content;
  };
}

export interface AWS_ApiGateway_DocumentationPart {
  Type: "AWS::ApiGateway::DocumentationPart";
  Properties: {
    Location: AWS_ApiGateway_DocumentationPart____Location;
    Properties: string;
    RestApiId: string;
  };
}

export interface AWS_CloudFront_CachePolicy {
  Type: "AWS::CloudFront::CachePolicy";
  Properties: {
    CachePolicyConfig: CachePolicyConfig;
  };
}

export interface AWS_ElastiCache_User {
  Type: "AWS::ElastiCache::User";
  Properties: {
    UserId: string;
    UserName: string;
    Engine: string;
    AccessString?: string;
    NoPasswordRequired?: boolean;
    Passwords?: Array<string>;
  };
}

export interface AWS_AppMesh_GatewayRoute {
  Type: "AWS::AppMesh::GatewayRoute";
  Properties: {
    MeshName: string;
    VirtualGatewayName: string;
    MeshOwner?: string;
    GatewayRouteName?: string;
    Spec: GatewayRouteSpec;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SageMaker_UserProfile {
  Type: "AWS::SageMaker::UserProfile";
  Properties: {
    DomainId: string;
    SingleSignOnUserIdentifier?: string;
    SingleSignOnUserValue?: string;
    UserProfileName: string;
    UserSettings?: AWS_SageMaker_UserProfile____UserSettings;
    Tags?: Array<Tag>;
  };
}

export interface AWS_RDS_DBSubnetGroup {
  Type: "AWS::RDS::DBSubnetGroup";
  Properties: {
    DBSubnetGroupDescription: string;
    DBSubnetGroupName?: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_LakeFormation_DataLakeSettings {
  Type: "AWS::LakeFormation::DataLakeSettings";
  Properties: {
    Admins?: Admins;
    TrustedResourceOwners?: Array<string>;
  };
}

export interface AWS_ElasticLoadBalancing_LoadBalancer {
  Type: "AWS::ElasticLoadBalancing::LoadBalancer";
  Properties: {
    AccessLoggingPolicy?: AccessLoggingPolicy;
    AppCookieStickinessPolicy?: Array<AppCookieStickinessPolicy>;
    AvailabilityZones?: Array<string>;
    ConnectionDrainingPolicy?: ConnectionDrainingPolicy;
    ConnectionSettings?: ConnectionSettings;
    CrossZone?: boolean;
    HealthCheck?: AWS_ElasticLoadBalancing_LoadBalancer____HealthCheck;
    Instances?: Array<string>;
    LBCookieStickinessPolicy?: Array<LBCookieStickinessPolicy>;
    Listeners: Array<Listeners>;
    LoadBalancerName?: string;
    Policies?: Array<AWS_ElasticLoadBalancing_LoadBalancer____Policies>;
    Scheme?: string;
    SecurityGroups?: Array<string>;
    Subnets?: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_IoTFleetHub_Application {
  Type: "AWS::IoTFleetHub::Application";
  Properties: {
    ApplicationName: string;
    ApplicationDescription?: string;
    RoleArn: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CodeArtifact_Repository {
  Type: "AWS::CodeArtifact::Repository";
  Properties: {
    RepositoryName: string;
    DomainName: string;
    DomainOwner?: string;
    Description?: string;
    ExternalConnections?: Array<string>;
    Upstreams?: Array<string>;
    PermissionsPolicyDocument?: any;
    Tags?: Array<Tag>;
  };
}

export interface AWS_MWAA_Environment {
  Type: "AWS::MWAA::Environment";
  Properties: {
    Name: string;
    ExecutionRoleArn?: string;
    KmsKey?: string;
    AirflowVersion?: string;
    SourceBucketArn?: string;
    DagS3Path?: string;
    PluginsS3Path?: string;
    PluginsS3ObjectVersion?: string;
    RequirementsS3Path?: string;
    RequirementsS3ObjectVersion?: string;
    AirflowConfigurationOptions?: any;
    EnvironmentClass?: string;
    MaxWorkers?: number;
    MinWorkers?: number;
    NetworkConfiguration?: AWS_MWAA_Environment____NetworkConfiguration;
    LoggingConfiguration?: AWS_MWAA_Environment____LoggingConfiguration;
    WeeklyMaintenanceWindowStart?: string;
    Tags?: TagMap;
    WebserverAccessMode?: string;
  };
}

export interface AWS_ApiGatewayV2_Stage {
  Type: "AWS::ApiGatewayV2::Stage";
  Properties: {
    ClientCertificateId?: string;
    DeploymentId?: string;
    Description?: string;
    AccessLogSettings?: AccessLogSettings;
    AutoDeploy?: boolean;
    RouteSettings?: any;
    StageName: string;
    StageVariables?: any;
    AccessPolicyId?: string;
    ApiId: string;
    DefaultRouteSettings?: RouteSettings;
    Tags?: any;
  };
}

export interface AWS_ApiGateway_Model {
  Type: "AWS::ApiGateway::Model";
  Properties: {
    ContentType?: string;
    Description?: string;
    Name?: string;
    RestApiId: string;
    Schema?: any;
  };
}

export interface AWS_SageMaker_ModelExplainabilityJobDefinition {
  Type: "AWS::SageMaker::ModelExplainabilityJobDefinition";
  Properties: {
    JobDefinitionName?: string;
    ModelExplainabilityBaselineConfig?: ModelExplainabilityBaselineConfig;
    ModelExplainabilityAppSpecification: ModelExplainabilityAppSpecification;
    ModelExplainabilityJobInput: ModelExplainabilityJobInput;
    ModelExplainabilityJobOutputConfig: AWS_SageMaker_ModelExplainabilityJobDefinition____MonitoringOutputConfig;
    JobResources: AWS_SageMaker_ModelExplainabilityJobDefinition____MonitoringResources;
    NetworkConfig?: AWS_SageMaker_ModelExplainabilityJobDefinition____NetworkConfig;
    RoleArn: string;
    StoppingCondition?: AWS_SageMaker_ModelExplainabilityJobDefinition____StoppingCondition;
    Tags?: Array<Tag>;
  };
}

export interface AWS_WAFRegional_RegexPatternSet {
  Type: "AWS::WAFRegional::RegexPatternSet";
  Properties: {
    RegexPatternStrings: Array<string>;
    Name: string;
  };
}

export interface AWS_GuardDuty_ThreatIntelSet {
  Type: "AWS::GuardDuty::ThreatIntelSet";
  Properties: {
    Format: string;
    Activate: boolean;
    DetectorId: string;
    Name?: string;
    Location: string;
  };
}

export interface AWS_Logs_MetricFilter {
  Type: "AWS::Logs::MetricFilter";
  Properties: {
    FilterPattern: string;
    LogGroupName: string;
    MetricTransformations: Array<MetricTransformation>;
  };
}

export interface AWS_Macie_Session {
  Type: "AWS::Macie::Session";
  Properties: {
    Status?: string;
    FindingPublishingFrequency?: string;
  };
}

export interface AWS_Glue_Workflow {
  Type: "AWS::Glue::Workflow";
  Properties: {
    Description?: string;
    DefaultRunProperties?: any;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_GroundStation_DataflowEndpointGroup {
  Type: "AWS::GroundStation::DataflowEndpointGroup";
  Properties: {
    EndpointDetails: Array<AWS_GroundStation_DataflowEndpointGroup____EndpointDetails>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Config_RemediationConfiguration {
  Type: "AWS::Config::RemediationConfiguration";
  Properties: {
    TargetVersion?: string;
    ExecutionControls?: ExecutionControls;
    Parameters?: any;
    TargetType: string;
    ConfigRuleName: string;
    ResourceType?: string;
    RetryAttemptSeconds?: number;
    MaximumAutomaticAttempts?: number;
    TargetId: string;
    Automatic?: boolean;
  };
}

export interface AWS_EC2_FlowLog {
  Type: "AWS::EC2::FlowLog";
  Properties: {
    DeliverLogsPermissionArn?: string;
    LogDestination?: string;
    LogDestinationType?: string;
    LogFormat?: string;
    LogGroupName?: string;
    MaxAggregationInterval?: number;
    ResourceId: string;
    ResourceType: string;
    Tags?: Array<Tag>;
    TrafficType: string;
  };
}

export interface AWS_SecretsManager_RotationSchedule {
  Type: "AWS::SecretsManager::RotationSchedule";
  Properties: {
    SecretId: string;
    HostedRotationLambda?: HostedRotationLambda;
    RotationLambdaARN?: string;
    RotationRules?: RotationRules;
  };
}

export interface AWS_Greengrass_ResourceDefinition {
  Type: "AWS::Greengrass::ResourceDefinition";
  Properties: {
    InitialVersion?: ResourceDefinitionVersion;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_Cognito_IdentityPool {
  Type: "AWS::Cognito::IdentityPool";
  Properties: {
    PushSync?: PushSync;
    CognitoIdentityProviders?: Array<CognitoIdentityProvider>;
    CognitoEvents?: any;
    DeveloperProviderName?: string;
    CognitoStreams?: CognitoStreams;
    IdentityPoolName?: string;
    AllowUnauthenticatedIdentities: boolean;
    SupportedLoginProviders?: any;
    SamlProviderARNs?: Array<string>;
    OpenIdConnectProviderARNs?: Array<string>;
    AllowClassicFlow?: boolean;
  };
}

export interface AWS_IAM_AccessKey {
  Type: "AWS::IAM::AccessKey";
  Properties: {
    Serial?: number;
    Status?: string;
    UserName: string;
  };
}

export interface AWS_ElasticLoadBalancingV2_LoadBalancer {
  Type: "AWS::ElasticLoadBalancingV2::LoadBalancer";
  Properties: {
    IpAddressType?: string;
    LoadBalancerAttributes?: Array<LoadBalancerAttribute>;
    Name?: string;
    Scheme?: string;
    SecurityGroups?: Array<string>;
    SubnetMappings?: Array<AWS_ElasticLoadBalancingV2_LoadBalancer____SubnetMapping>;
    Subnets?: Array<string>;
    Tags?: Array<Tag>;
    Type?: string;
  };
}

export interface AWS_GameLift_MatchmakingConfiguration {
  Type: "AWS::GameLift::MatchmakingConfiguration";
  Properties: {
    GameProperties?: Array<GameProperty>;
    GameSessionData?: string;
    Description?: string;
    AcceptanceTimeoutSeconds?: number;
    NotificationTarget?: string;
    CustomEventData?: string;
    Name: string;
    AdditionalPlayerCount?: number;
    BackfillMode?: string;
    RequestTimeoutSeconds: number;
    AcceptanceRequired: boolean;
    FlexMatchMode?: string;
    RuleSetName: string;
    GameSessionQueueArns?: Array<string>;
  };
}

export interface AWS_CodeBuild_SourceCredential {
  Type: "AWS::CodeBuild::SourceCredential";
  Properties: {
    ServerType: string;
    Username?: string;
    Token: string;
    AuthType: string;
  };
}

export interface AWS_AmazonMQ_ConfigurationAssociation {
  Type: "AWS::AmazonMQ::ConfigurationAssociation";
  Properties: {
    Broker: string;
    Configuration: AWS_AmazonMQ_ConfigurationAssociation____ConfigurationId;
  };
}

export interface AWS_DMS_ReplicationSubnetGroup {
  Type: "AWS::DMS::ReplicationSubnetGroup";
  Properties: {
    ReplicationSubnetGroupDescription: string;
    ReplicationSubnetGroupIdentifier?: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ECS_CapacityProvider {
  Type: "AWS::ECS::CapacityProvider";
  Properties: {
    AutoScalingGroupProvider: AutoScalingGroupProvider;
    Name?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SageMaker_ModelPackageGroup {
  Type: "AWS::SageMaker::ModelPackageGroup";
  Properties: {
    Tags?: Array<Tag>;
    ModelPackageGroupName: string;
    ModelPackageGroupDescription?: string;
    ModelPackageGroupPolicy?: any;
  };
}

export interface AWS_CodeBuild_Project {
  Type: "AWS::CodeBuild::Project";
  Properties: {
    Description?: string;
    VpcConfig?: AWS_CodeBuild_Project____VpcConfig;
    SecondarySources?: Array<AWS_CodeBuild_Project____Source>;
    EncryptionKey?: string;
    SourceVersion?: string;
    Triggers?: ProjectTriggers;
    SecondaryArtifacts?: Array<Artifacts>;
    Source: AWS_CodeBuild_Project____Source;
    Name?: string;
    Artifacts: Artifacts;
    BadgeEnabled?: boolean;
    LogsConfig?: LogsConfig;
    ServiceRole: string;
    QueuedTimeoutInMinutes?: number;
    FileSystemLocations?: Array<ProjectFileSystemLocation>;
    Environment: AWS_CodeBuild_Project____Environment;
    SecondarySourceVersions?: Array<ProjectSourceVersion>;
    ConcurrentBuildLimit?: number;
    BuildBatchConfig?: ProjectBuildBatchConfig;
    Tags?: Array<Tag>;
    TimeoutInMinutes?: number;
    Cache?: ProjectCache;
  };
}

export interface AWS_WAFv2_IPSet {
  Type: "AWS::WAFv2::IPSet";
  Properties: {
    Description?: string;
    Name?: string;
    Scope: string;
    IPAddressVersion: string;
    Addresses: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_S3ObjectLambda_AccessPoint {
  Type: "AWS::S3ObjectLambda::AccessPoint";
  Properties: {
    Name: string;
    ObjectLambdaConfiguration?: ObjectLambdaConfiguration;
  };
}

export interface AWS_Budgets_Budget {
  Type: "AWS::Budgets::Budget";
  Properties: {
    NotificationsWithSubscribers?: Array<NotificationWithSubscribers>;
    Budget: BudgetData;
  };
}

export interface AWS_Route53Resolver_FirewallRuleGroupAssociation {
  Type: "AWS::Route53Resolver::FirewallRuleGroupAssociation";
  Properties: {
    FirewallRuleGroupId: string;
    VpcId: string;
    Name?: string;
    Priority: number;
    MutationProtection?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_NetworkFirewall_RuleGroup {
  Type: "AWS::NetworkFirewall::RuleGroup";
  Properties: {
    RuleGroupName: string;
    RuleGroup?: AWS_NetworkFirewall_RuleGroup____RuleGroup;
    Type: string;
    Capacity: number;
    Description?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SNS_TopicPolicy {
  Type: "AWS::SNS::TopicPolicy";
  Properties: {
    PolicyDocument: any;
    Topics: Array<string>;
  };
}

export interface AWS_Lambda_Alias {
  Type: "AWS::Lambda::Alias";
  Properties: {
    Description?: string;
    FunctionName: string;
    FunctionVersion: string;
    Name: string;
    ProvisionedConcurrencyConfig?: AWS_Lambda_Alias____ProvisionedConcurrencyConfiguration;
    RoutingConfig?: AliasRoutingConfiguration;
  };
}

export interface AWS_ElasticLoadBalancingV2_Listener {
  Type: "AWS::ElasticLoadBalancingV2::Listener";
  Properties: {
    SslPolicy?: string;
    LoadBalancerArn: string;
    DefaultActions: Array<AWS_ElasticLoadBalancingV2_Listener____Action>;
    Port?: number;
    Certificates?: Array<AWS_ElasticLoadBalancingV2_Listener____Certificate>;
    Protocol?: string;
    AlpnPolicy?: Array<string>;
  };
}

export interface AWS_EC2_SecurityGroupEgress {
  Type: "AWS::EC2::SecurityGroupEgress";
  Properties: {
    CidrIp?: string;
    CidrIpv6?: string;
    Description?: string;
    DestinationPrefixListId?: string;
    DestinationSecurityGroupId?: string;
    FromPort?: number;
    GroupId: string;
    IpProtocol: string;
    ToPort?: number;
  };
}

export interface AWS_Lambda_LayerVersionPermission {
  Type: "AWS::Lambda::LayerVersionPermission";
  Properties: {
    Action: string;
    LayerVersionArn: string;
    OrganizationId?: string;
    Principal: string;
  };
}

export interface AWS_SageMaker_EndpointConfig {
  Type: "AWS::SageMaker::EndpointConfig";
  Properties: {
    DataCaptureConfig?: DataCaptureConfig;
    ProductionVariants: Array<ProductionVariant>;
    KmsKeyId?: string;
    EndpointConfigName?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Events_Connection {
  Type: "AWS::Events::Connection";
  Properties: {
    Name?: string;
    Description?: string;
    AuthorizationType: string;
    AuthParameters: any;
  };
}

export interface AWS_Greengrass_DeviceDefinition {
  Type: "AWS::Greengrass::DeviceDefinition";
  Properties: {
    InitialVersion?: DeviceDefinitionVersion;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_StepFunctions_StateMachine {
  Type: "AWS::StepFunctions::StateMachine";
  Properties: {
    DefinitionString?: string;
    RoleArn: string;
    StateMachineName?: string;
    StateMachineType?: string;
    LoggingConfiguration?: AWS_StepFunctions_StateMachine____LoggingConfiguration;
    TracingConfiguration?: TracingConfiguration;
    DefinitionS3Location?: AWS_StepFunctions_StateMachine____S3Location;
    DefinitionSubstitutions?: Record<string, string>;
    Definition?: AWS_StepFunctions_StateMachine____Definition;
    Tags?: Array<AWS_StepFunctions_StateMachine____TagsEntry>;
  };
}

export interface AWS_IoT_MitigationAction {
  Type: "AWS::IoT::MitigationAction";
  Properties: {
    ActionName?: string;
    RoleArn: string;
    Tags?: Array<Tag>;
    ActionParams: ActionParams;
  };
}

export interface AWS_DMS_EventSubscription {
  Type: "AWS::DMS::EventSubscription";
  Properties: {
    SourceType?: string;
    EventCategories?: Array<string>;
    Enabled?: boolean;
    SubscriptionName?: string;
    SnsTopicArn: string;
    SourceIds?: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CodeDeploy_DeploymentConfig {
  Type: "AWS::CodeDeploy::DeploymentConfig";
  Properties: {
    DeploymentConfigName?: string;
    MinimumHealthyHosts?: MinimumHealthyHosts;
  };
}

export interface AWS_EC2_TransitGatewayAttachment {
  Type: "AWS::EC2::TransitGatewayAttachment";
  Properties: {
    TransitGatewayId: string;
    VpcId: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_FraudDetector_Outcome {
  Type: "AWS::FraudDetector::Outcome";
  Properties: {
    Name: string;
    Tags?: Array<Tag>;
    Description?: string;
  };
}

export interface AWS_DataSync_LocationFSxWindows {
  Type: "AWS::DataSync::LocationFSxWindows";
  Properties: {
    Domain?: string;
    FsxFilesystemArn: string;
    Password: string;
    SecurityGroupArns: Array<string>;
    Subdirectory?: string;
    User: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_IoT_SecurityProfile {
  Type: "AWS::IoT::SecurityProfile";
  Properties: {
    SecurityProfileName?: string;
    SecurityProfileDescription?: string;
    Behaviors?: Array<Behavior>;
    AlertTargets?: Record<string, AlertTarget>;
    AdditionalMetricsToRetainV2?: Array<MetricToRetain>;
    Tags?: Array<Tag>;
    TargetArns?: Array<string>;
  };
}

export interface AWS_MediaConnect_FlowVpcInterface {
  Type: "AWS::MediaConnect::FlowVpcInterface";
  Properties: {
    FlowArn: string;
    Name: string;
    RoleArn: string;
    SecurityGroupIds: Array<string>;
    SubnetId: string;
  };
}

export interface AWS_Config_ConfigurationAggregator {
  Type: "AWS::Config::ConfigurationAggregator";
  Properties: {
    AccountAggregationSources?: Array<AccountAggregationSource>;
    ConfigurationAggregatorName: string;
    OrganizationAggregationSource?: OrganizationAggregationSource;
    Tags?: Array<Tag>;
  };
}

export interface AWS_S3_StorageLens {
  Type: "AWS::S3::StorageLens";
  Properties: {
    StorageLensConfiguration: StorageLensConfiguration;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CloudFront_Distribution {
  Type: "AWS::CloudFront::Distribution";
  Properties: {
    DistributionConfig: DistributionConfig;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Redshift_ClusterParameterGroup {
  Type: "AWS::Redshift::ClusterParameterGroup";
  Properties: {
    Description: string;
    ParameterGroupFamily: string;
    Parameters?: Array<AWS_Redshift_ClusterParameterGroup____Parameter>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_DataSync_LocationS3 {
  Type: "AWS::DataSync::LocationS3";
  Properties: {
    S3Config: S3Config;
    S3BucketArn: string;
    Subdirectory?: string;
    S3StorageClass?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ElastiCache_UserGroup {
  Type: "AWS::ElastiCache::UserGroup";
  Properties: {
    UserGroupId: string;
    Engine: string;
    UserIds?: Array<string>;
  };
}

export interface AWS_CloudTrail_Trail {
  Type: "AWS::CloudTrail::Trail";
  Properties: {
    CloudWatchLogsLogGroupArn?: string;
    CloudWatchLogsRoleArn?: string;
    EnableLogFileValidation?: boolean;
    EventSelectors?: Array<EventSelector>;
    IncludeGlobalServiceEvents?: boolean;
    IsLogging: boolean;
    IsMultiRegionTrail?: boolean;
    KMSKeyId?: string;
    S3BucketName: string;
    S3KeyPrefix?: string;
    SnsTopicName?: string;
    Tags?: Array<Tag>;
    TrailName?: string;
  };
}

export interface AWS_EMR_InstanceGroupConfig {
  Type: "AWS::EMR::InstanceGroupConfig";
  Properties: {
    AutoScalingPolicy?: AWS_EMR_InstanceGroupConfig____AutoScalingPolicy;
    BidPrice?: string;
    Configurations?: Array<AWS_EMR_InstanceGroupConfig____Configuration>;
    EbsConfiguration?: AWS_EMR_InstanceGroupConfig____EbsConfiguration;
    InstanceCount: number;
    InstanceRole: string;
    InstanceType: string;
    JobFlowId: string;
    Market?: string;
    Name?: string;
  };
}

export interface AWS_Neptune_DBClusterParameterGroup {
  Type: "AWS::Neptune::DBClusterParameterGroup";
  Properties: {
    Description: string;
    Parameters: any;
    Family: string;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_ElasticLoadBalancingV2_ListenerRule {
  Type: "AWS::ElasticLoadBalancingV2::ListenerRule";
  Properties: {
    ListenerArn: string;
    Actions: Array<AWS_ElasticLoadBalancingV2_ListenerRule____Action>;
    Priority: number;
    Conditions: Array<RuleCondition>;
  };
}

export interface AWS_CodePipeline_Pipeline {
  Type: "AWS::CodePipeline::Pipeline";
  Properties: {
    ArtifactStore?: ArtifactStore;
    ArtifactStores?: Array<ArtifactStoreMap>;
    DisableInboundStageTransitions?: Array<StageTransition>;
    Name?: string;
    RestartExecutionOnUpdate?: boolean;
    RoleArn: string;
    Stages: Array<StageDeclaration>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_MediaConnect_FlowEntitlement {
  Type: "AWS::MediaConnect::FlowEntitlement";
  Properties: {
    FlowArn: string;
    DataTransferSubscriberFeePercent?: number;
    Description: string;
    Encryption?: AWS_MediaConnect_FlowEntitlement____Encryption;
    EntitlementStatus?: string;
    Name: string;
    Subscribers: Array<string>;
  };
}

export interface AWS_IoT_TopicRule {
  Type: "AWS::IoT::TopicRule";
  Properties: {
    RuleName?: string;
    TopicRulePayload: TopicRulePayload;
    Tags?: Array<Tag>;
  };
}

export interface AWS_DocDB_DBInstance {
  Type: "AWS::DocDB::DBInstance";
  Properties: {
    DBInstanceClass: string;
    DBClusterIdentifier: string;
    AvailabilityZone?: string;
    PreferredMaintenanceWindow?: string;
    AutoMinorVersionUpgrade?: boolean;
    DBInstanceIdentifier?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_OpsWorks_ElasticLoadBalancerAttachment {
  Type: "AWS::OpsWorks::ElasticLoadBalancerAttachment";
  Properties: {
    ElasticLoadBalancerName: string;
    LayerId: string;
  };
}

export interface AWS_ServiceCatalogAppRegistry_Application {
  Type: "AWS::ServiceCatalogAppRegistry::Application";
  Properties: {
    Name: string;
    Description?: string;
    Tags?: Record<string, string>;
  };
}

export interface AWS_WAFRegional_WebACLAssociation {
  Type: "AWS::WAFRegional::WebACLAssociation";
  Properties: {
    ResourceArn: string;
    WebACLId: string;
  };
}

export interface AWS_ServiceCatalog_CloudFormationProduct {
  Type: "AWS::ServiceCatalog::CloudFormationProduct";
  Properties: {
    ReplaceProvisioningArtifacts?: boolean;
    Owner: string;
    SupportDescription?: string;
    Description?: string;
    Distributor?: string;
    SupportEmail?: string;
    AcceptLanguage?: string;
    SupportUrl?: string;
    Tags?: Array<Tag>;
    Name: string;
    ProvisioningArtifactParameters: Array<ProvisioningArtifactProperties>;
  };
}

export interface AWS_GreengrassV2_ComponentVersion {
  Type: "AWS::GreengrassV2::ComponentVersion";
  Properties: {
    InlineRecipe?: string;
    LambdaFunction?: LambdaFunctionRecipeSource;
    Tags?: Record<string, string>;
  };
}

export interface AWS_RoboMaker_SimulationApplication {
  Type: "AWS::RoboMaker::SimulationApplication";
  Properties: {
    RenderingEngine: RenderingEngine;
    SimulationSoftwareSuite: SimulationSoftwareSuite;
    CurrentRevisionId?: string;
    RobotSoftwareSuite: AWS_RoboMaker_SimulationApplication____RobotSoftwareSuite;
    Sources: Array<AWS_RoboMaker_SimulationApplication____SourceConfig>;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_IoTAnalytics_Channel {
  Type: "AWS::IoTAnalytics::Channel";
  Properties: {
    ChannelName?: string;
    ChannelStorage?: ChannelStorage;
    RetentionPeriod?: AWS_IoTAnalytics_Channel____RetentionPeriod;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Amplify_App {
  Type: "AWS::Amplify::App";
  Properties: {
    AutoBranchCreationConfig?: AutoBranchCreationConfig;
    OauthToken?: string;
    Description?: string;
    EnableBranchAutoDeletion?: boolean;
    Name: string;
    Repository?: string;
    EnvironmentVariables?: Array<AWS_Amplify_App____EnvironmentVariable>;
    AccessToken?: string;
    BuildSpec?: string;
    CustomRules?: Array<CustomRule>;
    BasicAuthConfig?: AWS_Amplify_App____BasicAuthConfig;
    CustomHeaders?: string;
    Tags?: Array<Tag>;
    IAMServiceRole?: string;
  };
}

export interface AWS_EventSchemas_Discoverer {
  Type: "AWS::EventSchemas::Discoverer";
  Properties: {
    Description?: string;
    SourceArn: string;
    Tags?: Array<AWS_EventSchemas_Discoverer____TagsEntry>;
  };
}

export interface AWS_CloudWatch_AnomalyDetector {
  Type: "AWS::CloudWatch::AnomalyDetector";
  Properties: {
    MetricName: string;
    Stat: string;
    Configuration?: AWS_CloudWatch_AnomalyDetector____Configuration;
    Dimensions?: Array<AWS_CloudWatch_AnomalyDetector____Dimension>;
    Namespace: string;
  };
}

export interface AWS_Cloud9_EnvironmentEC2 {
  Type: "AWS::Cloud9::EnvironmentEC2";
  Properties: {
    Repositories?: Array<Repository>;
    OwnerArn?: string;
    Description?: string;
    ConnectionType?: string;
    AutomaticStopTimeMinutes?: number;
    ImageId?: string;
    SubnetId?: string;
    InstanceType: string;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_WAFRegional_WebACL {
  Type: "AWS::WAFRegional::WebACL";
  Properties: {
    MetricName: string;
    DefaultAction: AWS_WAFRegional_WebACL____Action;
    Rules?: Array<AWS_WAFRegional_WebACL____Rule>;
    Name: string;
  };
}

export interface AWS_CloudFront_CloudFrontOriginAccessIdentity {
  Type: "AWS::CloudFront::CloudFrontOriginAccessIdentity";
  Properties: {
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentityConfig;
  };
}

export interface AWS_SageMaker_Endpoint {
  Type: "AWS::SageMaker::Endpoint";
  Properties: {
    RetainAllVariantProperties?: boolean;
    EndpointName?: string;
    ExcludeRetainedVariantProperties?: Array<VariantProperty>;
    EndpointConfigName: string;
    DeploymentConfig?: DeploymentConfig;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SageMaker_ModelBiasJobDefinition {
  Type: "AWS::SageMaker::ModelBiasJobDefinition";
  Properties: {
    JobDefinitionName?: string;
    ModelBiasBaselineConfig?: ModelBiasBaselineConfig;
    ModelBiasAppSpecification: ModelBiasAppSpecification;
    ModelBiasJobInput: ModelBiasJobInput;
    ModelBiasJobOutputConfig: AWS_SageMaker_ModelBiasJobDefinition____MonitoringOutputConfig;
    JobResources: AWS_SageMaker_ModelBiasJobDefinition____MonitoringResources;
    NetworkConfig?: AWS_SageMaker_ModelBiasJobDefinition____NetworkConfig;
    RoleArn: string;
    StoppingCondition?: AWS_SageMaker_ModelBiasJobDefinition____StoppingCondition;
    Tags?: Array<Tag>;
  };
}

export interface AWS_AppSync_ApiKey {
  Type: "AWS::AppSync::ApiKey";
  Properties: {
    Description?: string;
    ApiKeyId?: string;
    Expires?: number;
    ApiId: string;
  };
}

export interface AWS_Route53_HostedZone {
  Type: "AWS::Route53::HostedZone";
  Properties: {
    HostedZoneConfig?: HostedZoneConfig;
    HostedZoneTags?: Array<HostedZoneTag>;
    Name: string;
    QueryLoggingConfig?: QueryLoggingConfig;
    VPCs?: Array<VPC>;
  };
}

export interface AWS_EC2_Subnet {
  Type: "AWS::EC2::Subnet";
  Properties: {
    AssignIpv6AddressOnCreation?: boolean;
    AvailabilityZone?: string;
    CidrBlock: string;
    Ipv6CidrBlock?: string;
    MapPublicIpOnLaunch?: boolean;
    OutpostArn?: string;
    Tags?: Array<Tag>;
    VpcId: string;
  };
}

export interface AWS_CodeDeploy_Application {
  Type: "AWS::CodeDeploy::Application";
  Properties: {
    ApplicationName?: string;
    ComputePlatform?: string;
  };
}

export interface AWS_ServiceCatalog_PortfolioProductAssociation {
  Type: "AWS::ServiceCatalog::PortfolioProductAssociation";
  Properties: {
    SourcePortfolioId?: string;
    AcceptLanguage?: string;
    PortfolioId: string;
    ProductId: string;
  };
}

export interface AWS_EC2_TransitGatewayMulticastDomainAssociation {
  Type: "AWS::EC2::TransitGatewayMulticastDomainAssociation";
  Properties: {
    TransitGatewayMulticastDomainId: string;
    TransitGatewayAttachmentId: string;
    SubnetId: string;
  };
}

export interface AWS_ServiceDiscovery_Instance {
  Type: "AWS::ServiceDiscovery::Instance";
  Properties: {
    InstanceAttributes: any;
    InstanceId?: string;
    ServiceId: string;
  };
}

export interface AWS_AppConfig_HostedConfigurationVersion {
  Type: "AWS::AppConfig::HostedConfigurationVersion";
  Properties: {
    ConfigurationProfileId: string;
    Description?: string;
    ContentType: string;
    LatestVersionNumber?: number;
    Content: string;
    ApplicationId: string;
  };
}

export interface AWS_MediaConvert_JobTemplate {
  Type: "AWS::MediaConvert::JobTemplate";
  Properties: {
    Category?: string;
    Description?: string;
    AccelerationSettings?: AccelerationSettings;
    Priority?: number;
    StatusUpdateInterval?: string;
    SettingsJson: any;
    Queue?: string;
    HopDestinations?: Array<HopDestination>;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_EC2_Instance {
  Type: "AWS::EC2::Instance";
  Properties: {
    AdditionalInfo?: string;
    Affinity?: string;
    AvailabilityZone?: string;
    BlockDeviceMappings?: Array<AWS_EC2_Instance____BlockDeviceMapping>;
    CpuOptions?: AWS_EC2_Instance____CpuOptions;
    CreditSpecification?: AWS_EC2_Instance____CreditSpecification;
    DisableApiTermination?: boolean;
    EbsOptimized?: boolean;
    ElasticGpuSpecifications?: Array<AWS_EC2_Instance____ElasticGpuSpecification>;
    ElasticInferenceAccelerators?: Array<ElasticInferenceAccelerator>;
    EnclaveOptions?: AWS_EC2_Instance____EnclaveOptions;
    HibernationOptions?: AWS_EC2_Instance____HibernationOptions;
    HostId?: string;
    HostResourceGroupArn?: string;
    IamInstanceProfile?: string;
    ImageId?: string;
    InstanceInitiatedShutdownBehavior?: string;
    InstanceType?: string;
    Ipv6AddressCount?: number;
    Ipv6Addresses?: Array<AWS_EC2_Instance____InstanceIpv6Address>;
    KernelId?: string;
    KeyName?: string;
    LaunchTemplate?: AWS_EC2_Instance____LaunchTemplateSpecification;
    LicenseSpecifications?: Array<AWS_EC2_Instance____LicenseSpecification>;
    Monitoring?: boolean;
    NetworkInterfaces?: Array<AWS_EC2_Instance____NetworkInterface>;
    PlacementGroupName?: string;
    PrivateIpAddress?: string;
    RamdiskId?: string;
    SecurityGroupIds?: Array<string>;
    SecurityGroups?: Array<string>;
    SourceDestCheck?: boolean;
    SsmAssociations?: Array<SsmAssociation>;
    SubnetId?: string;
    Tags?: Array<Tag>;
    Tenancy?: string;
    UserData?: string;
    Volumes?: Array<AWS_EC2_Instance____Volume>;
  };
}

export interface AWS_Events_EventBusPolicy {
  Type: "AWS::Events::EventBusPolicy";
  Properties: {
    EventBusName?: string;
    Condition?: AWS_Events_EventBusPolicy____Condition;
    Action?: string;
    StatementId: string;
    Statement?: any;
    Principal?: string;
  };
}

export interface AWS_EKS_Cluster {
  Type: "AWS::EKS::Cluster";
  Properties: {
    Version?: string;
    EncryptionConfig?: Array<EncryptionConfig>;
    RoleArn: string;
    ResourcesVpcConfig: ResourcesVpcConfig;
    KubernetesNetworkConfig?: KubernetesNetworkConfig;
    Name?: string;
  };
}

export interface AWS_CloudFormation_Stack {
  Type: "AWS::CloudFormation::Stack";
  Properties: {
    NotificationARNs?: Array<string>;
    Parameters?: Record<string, string>;
    Tags?: Array<Tag>;
    TemplateURL: string;
    TimeoutInMinutes?: number;
  };
}

export interface AWS_WAF_ByteMatchSet {
  Type: "AWS::WAF::ByteMatchSet";
  Properties: {
    ByteMatchTuples?: Array<AWS_WAF_ByteMatchSet____ByteMatchTuple>;
    Name: string;
  };
}

export interface AWS_Config_AggregationAuthorization {
  Type: "AWS::Config::AggregationAuthorization";
  Properties: {
    AuthorizedAccountId: string;
    AuthorizedAwsRegion: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_DocDB_DBCluster {
  Type: "AWS::DocDB::DBCluster";
  Properties: {
    StorageEncrypted?: boolean;
    EngineVersion?: string;
    KmsKeyId?: string;
    AvailabilityZones?: Array<string>;
    SnapshotIdentifier?: string;
    Port?: number;
    DBClusterIdentifier?: string;
    PreferredMaintenanceWindow?: string;
    DBSubnetGroupName?: string;
    DeletionProtection?: boolean;
    PreferredBackupWindow?: string;
    MasterUserPassword: string;
    VpcSecurityGroupIds?: Array<string>;
    MasterUsername: string;
    DBClusterParameterGroupName?: string;
    BackupRetentionPeriod?: number;
    Tags?: Array<Tag>;
    EnableCloudwatchLogsExports?: Array<string>;
  };
}

export interface AWS_FIS_ExperimentTemplate {
  Type: "AWS::FIS::ExperimentTemplate";
  Properties: {
    Description: string;
    Targets: Record<string, ExperimentTemplateTarget>;
    Actions?: Record<string, ExperimentTemplateAction>;
    StopConditions: Array<ExperimentTemplateStopCondition>;
    RoleArn: string;
    Tags: Record<string, string>;
  };
}

export interface AWS_CloudWatch_CompositeAlarm {
  Type: "AWS::CloudWatch::CompositeAlarm";
  Properties: {
    AlarmName: string;
    AlarmRule: string;
    AlarmDescription?: string;
    ActionsEnabled?: boolean;
    OKActions?: Array<string>;
    AlarmActions?: Array<string>;
    InsufficientDataActions?: Array<string>;
  };
}

export interface AWS_RDS_GlobalCluster {
  Type: "AWS::RDS::GlobalCluster";
  Properties: {
    Engine?: string;
    EngineVersion?: string;
    DeletionProtection?: boolean;
    GlobalClusterIdentifier?: string;
    SourceDBClusterIdentifier?: string;
    StorageEncrypted?: boolean;
  };
}

export interface AWS_SSM_PatchBaseline {
  Type: "AWS::SSM::PatchBaseline";
  Properties: {
    OperatingSystem?: string;
    Description?: string;
    ApprovalRules?: AWS_SSM_PatchBaseline____RuleGroup;
    Sources?: Array<PatchSource>;
    Name: string;
    RejectedPatches?: Array<string>;
    ApprovedPatches?: Array<string>;
    RejectedPatchesAction?: string;
    PatchGroups?: Array<string>;
    ApprovedPatchesComplianceLevel?: string;
    ApprovedPatchesEnableNonSecurity?: boolean;
    GlobalFilters?: PatchFilterGroup;
    Tags?: Array<Tag>;
  };
}

export interface AWS_IoT_DomainConfiguration {
  Type: "AWS::IoT::DomainConfiguration";
  Properties: {
    DomainConfigurationName?: string;
    AuthorizerConfig?: AuthorizerConfig;
    DomainName?: string;
    ServerCertificateArns?: Array<string>;
    ServiceType?: string;
    ValidationCertificateArn?: string;
    DomainConfigurationStatus?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_KinesisAnalyticsV2_ApplicationCloudWatchLoggingOption {
  Type: "AWS::KinesisAnalyticsV2::ApplicationCloudWatchLoggingOption";
  Properties: {
    ApplicationName: string;
    CloudWatchLoggingOption: CloudWatchLoggingOption;
  };
}

export interface AWS_AppMesh_VirtualGateway {
  Type: "AWS::AppMesh::VirtualGateway";
  Properties: {
    VirtualGatewayName?: string;
    MeshName: string;
    MeshOwner?: string;
    Spec: VirtualGatewaySpec;
    Tags?: Array<Tag>;
  };
}

export interface AWS_GuardDuty_Member {
  Type: "AWS::GuardDuty::Member";
  Properties: {
    Status?: string;
    MemberId: string;
    Email: string;
    Message?: string;
    DisableEmailNotification?: boolean;
    DetectorId: string;
  };
}

export interface AWS_ServiceCatalog_AcceptedPortfolioShare {
  Type: "AWS::ServiceCatalog::AcceptedPortfolioShare";
  Properties: {
    AcceptLanguage?: string;
    PortfolioId: string;
  };
}

export interface AWS_ServiceDiscovery_Service {
  Type: "AWS::ServiceDiscovery::Service";
  Properties: {
    Type?: string;
    Description?: string;
    HealthCheckCustomConfig?: HealthCheckCustomConfig;
    DnsConfig?: DnsConfig;
    NamespaceId?: string;
    HealthCheckConfig?: HealthCheckConfig;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_SecretsManager_ResourcePolicy {
  Type: "AWS::SecretsManager::ResourcePolicy";
  Properties: {
    BlockPublicPolicy?: boolean;
    SecretId: string;
    ResourcePolicy: any;
  };
}

export interface AWS_DevOpsGuru_NotificationChannel {
  Type: "AWS::DevOpsGuru::NotificationChannel";
  Properties: {
    Config: NotificationChannelConfig;
  };
}

export interface AWS_RoboMaker_SimulationApplicationVersion {
  Type: "AWS::RoboMaker::SimulationApplicationVersion";
  Properties: {
    CurrentRevisionId?: string;
    Application: string;
  };
}

export interface AWS_AuditManager_Assessment {
  Type: "AWS::AuditManager::Assessment";
  Properties: {
    FrameworkId?: string;
    AwsAccount?: AWSAccount;
    Tags?: Array<Tag>;
    Roles?: Array<Role>;
    Scope?: AWS_AuditManager_Assessment____Scope;
    AssessmentReportsDestination?: AssessmentReportsDestination;
    Status?: string;
    Name?: string;
    Description?: string;
  };
}

export interface AWS_AutoScaling_ScalingPolicy {
  Type: "AWS::AutoScaling::ScalingPolicy";
  Properties: {
    AdjustmentType?: string;
    AutoScalingGroupName: string;
    Cooldown?: string;
    EstimatedInstanceWarmup?: number;
    MetricAggregationType?: string;
    MinAdjustmentMagnitude?: number;
    PolicyType?: string;
    ScalingAdjustment?: number;
    StepAdjustments?: Array<AWS_AutoScaling_ScalingPolicy____StepAdjustment>;
    TargetTrackingConfiguration?: AWS_AutoScaling_ScalingPolicy____TargetTrackingConfiguration;
  };
}

export interface AWS_Backup_BackupVault {
  Type: "AWS::Backup::BackupVault";
  Properties: {
    AccessPolicy?: any;
    BackupVaultName: string;
    BackupVaultTags?: Record<string, string>;
    EncryptionKeyArn?: string;
    Notifications?: NotificationObjectType;
  };
}

export interface AWS_Config_ConfigurationRecorder {
  Type: "AWS::Config::ConfigurationRecorder";
  Properties: {
    Name?: string;
    RecordingGroup?: RecordingGroup;
    RoleARN: string;
  };
}

export interface AWS_EMR_Step {
  Type: "AWS::EMR::Step";
  Properties: {
    ActionOnFailure: string;
    HadoopJarStep: AWS_EMR_Step____HadoopJarStepConfig;
    JobFlowId: string;
    Name: string;
  };
}

export interface AWS_AppConfig_ConfigurationProfile {
  Type: "AWS::AppConfig::ConfigurationProfile";
  Properties: {
    LocationUri: string;
    Description?: string;
    Validators?: Array<Validators>;
    RetrievalRoleArn?: string;
    ApplicationId: string;
    Tags?: Array<AWS_AppConfig_ConfigurationProfile____Tags>;
    Name: string;
  };
}

export interface AWS_SSM_MaintenanceWindowTarget {
  Type: "AWS::SSM::MaintenanceWindowTarget";
  Properties: {
    OwnerInformation?: string;
    Description?: string;
    WindowId: string;
    ResourceType: string;
    Targets: Array<AWS_SSM_MaintenanceWindowTarget____Targets>;
    Name?: string;
  };
}

export interface AWS_IoT1Click_Placement {
  Type: "AWS::IoT1Click::Placement";
  Properties: {
    PlacementName?: string;
    ProjectName: string;
    AssociatedDevices?: any;
    Attributes?: any;
  };
}

export interface AWS_IoT_AccountAuditConfiguration {
  Type: "AWS::IoT::AccountAuditConfiguration";
  Properties: {
    AccountId: string;
    AuditCheckConfigurations: AuditCheckConfigurations;
    AuditNotificationTargetConfigurations?: AuditNotificationTargetConfigurations;
    RoleArn: string;
  };
}

export interface AWS_EC2_DHCPOptions {
  Type: "AWS::EC2::DHCPOptions";
  Properties: {
    DomainName?: string;
    DomainNameServers?: Array<string>;
    NetbiosNameServers?: Array<string>;
    NetbiosNodeType?: number;
    NtpServers?: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ApiGateway_UsagePlan {
  Type: "AWS::ApiGateway::UsagePlan";
  Properties: {
    ApiStages?: Array<ApiStage>;
    Description?: string;
    Quota?: QuotaSettings;
    Tags?: Array<Tag>;
    Throttle?: ThrottleSettings;
    UsagePlanName?: string;
  };
}

export interface AWS_IAM_User {
  Type: "AWS::IAM::User";
  Properties: {
    Groups?: Array<string>;
    LoginProfile?: LoginProfile;
    ManagedPolicyArns?: Array<string>;
    Path?: string;
    PermissionsBoundary?: string;
    Policies?: Array<AWS_IAM_User____Policy>;
    Tags?: Array<Tag>;
    UserName?: string;
  };
}

export interface AWS_Cognito_UserPoolResourceServer {
  Type: "AWS::Cognito::UserPoolResourceServer";
  Properties: {
    UserPoolId: string;
    Identifier: string;
    Scopes?: Array<ResourceServerScopeType>;
    Name: string;
  };
}

export interface AWS_OpsWorks_Instance {
  Type: "AWS::OpsWorks::Instance";
  Properties: {
    AgentVersion?: string;
    AmiId?: string;
    Architecture?: string;
    AutoScalingType?: string;
    AvailabilityZone?: string;
    BlockDeviceMappings?: Array<AWS_OpsWorks_Instance____BlockDeviceMapping>;
    EbsOptimized?: boolean;
    ElasticIps?: Array<string>;
    Hostname?: string;
    InstallUpdatesOnBoot?: boolean;
    InstanceType: string;
    LayerIds: Array<string>;
    Os?: string;
    RootDeviceType?: string;
    SshKeyName?: string;
    StackId: string;
    SubnetId?: string;
    Tenancy?: string;
    TimeBasedAutoScaling?: TimeBasedAutoScaling;
    VirtualizationType?: string;
    Volumes?: Array<string>;
  };
}

export interface AWS_CloudWatch_InsightRule {
  Type: "AWS::CloudWatch::InsightRule";
  Properties: {
    RuleState: string;
    RuleBody: string;
    RuleName: string;
    Tags?: AWS_CloudWatch_InsightRule____Tags;
  };
}

export interface AWS_ManagedBlockchain_Node {
  Type: "AWS::ManagedBlockchain::Node";
  Properties: {
    MemberId: string;
    NetworkId: string;
    NodeConfiguration: NodeConfiguration;
  };
}

export interface AWS_Detective_MemberInvitation {
  Type: "AWS::Detective::MemberInvitation";
  Properties: {
    GraphArn: string;
    MemberId: string;
    MemberEmailAddress: string;
    DisableEmailNotification?: boolean;
    Message?: string;
  };
}

export interface AWS_IoTAnalytics_Datastore {
  Type: "AWS::IoTAnalytics::Datastore";
  Properties: {
    DatastoreStorage?: DatastoreStorage;
    FileFormatConfiguration?: FileFormatConfiguration;
    DatastoreName?: string;
    RetentionPeriod?: AWS_IoTAnalytics_Datastore____RetentionPeriod;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Glue_Job {
  Type: "AWS::Glue::Job";
  Properties: {
    Connections?: ConnectionsList;
    MaxRetries?: number;
    Description?: string;
    Timeout?: number;
    AllocatedCapacity?: number;
    Name?: string;
    Role: string;
    DefaultArguments?: any;
    NotificationProperty?: AWS_Glue_Job____NotificationProperty;
    WorkerType?: string;
    LogUri?: string;
    Command: JobCommand;
    GlueVersion?: string;
    ExecutionProperty?: ExecutionProperty;
    SecurityConfiguration?: string;
    NumberOfWorkers?: number;
    Tags?: any;
    MaxCapacity?: number;
  };
}

export interface AWS_S3_Bucket {
  Type: "AWS::S3::Bucket";
  Properties: {
    AccelerateConfiguration?: AccelerateConfiguration;
    AccessControl?: string;
    AnalyticsConfigurations?: Array<AWS_S3_Bucket____AnalyticsConfiguration>;
    BucketEncryption?: BucketEncryption;
    BucketName?: string;
    CorsConfiguration?: CorsConfiguration;
    IntelligentTieringConfigurations?: Array<IntelligentTieringConfiguration>;
    InventoryConfigurations?: Array<InventoryConfiguration>;
    LifecycleConfiguration?: AWS_S3_Bucket____LifecycleConfiguration;
    LoggingConfiguration?: AWS_S3_Bucket____LoggingConfiguration;
    MetricsConfigurations?: Array<MetricsConfiguration>;
    NotificationConfiguration?: AWS_S3_Bucket____NotificationConfiguration;
    ObjectLockConfiguration?: ObjectLockConfiguration;
    ObjectLockEnabled?: boolean;
    OwnershipControls?: OwnershipControls;
    PublicAccessBlockConfiguration?: AWS_S3_Bucket____PublicAccessBlockConfiguration;
    ReplicationConfiguration?: AWS_S3_Bucket____ReplicationConfiguration;
    Tags?: Array<Tag>;
    VersioningConfiguration?: AWS_S3_Bucket____VersioningConfiguration;
    WebsiteConfiguration?: WebsiteConfiguration;
  };
}

export interface AWS_SageMaker_ModelQualityJobDefinition {
  Type: "AWS::SageMaker::ModelQualityJobDefinition";
  Properties: {
    JobDefinitionName?: string;
    ModelQualityBaselineConfig?: ModelQualityBaselineConfig;
    ModelQualityAppSpecification: ModelQualityAppSpecification;
    ModelQualityJobInput: ModelQualityJobInput;
    ModelQualityJobOutputConfig: AWS_SageMaker_ModelQualityJobDefinition____MonitoringOutputConfig;
    JobResources: AWS_SageMaker_ModelQualityJobDefinition____MonitoringResources;
    NetworkConfig?: AWS_SageMaker_ModelQualityJobDefinition____NetworkConfig;
    RoleArn: string;
    StoppingCondition?: AWS_SageMaker_ModelQualityJobDefinition____StoppingCondition;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Synthetics_Canary {
  Type: "AWS::Synthetics::Canary";
  Properties: {
    Name: string;
    Code: AWS_Synthetics_Canary____Code;
    ArtifactS3Location: string;
    Schedule: AWS_Synthetics_Canary____Schedule;
    ExecutionRoleArn: string;
    RuntimeVersion: string;
    SuccessRetentionPeriod?: number;
    FailureRetentionPeriod?: number;
    Tags?: Array<Tag>;
    VPCConfig?: VPCConfig;
    RunConfig?: RunConfig;
    StartCanaryAfterCreation: boolean;
  };
}

export interface AWS_Lambda_Version {
  Type: "AWS::Lambda::Version";
  Properties: {
    CodeSha256?: string;
    Description?: string;
    FunctionName: string;
    ProvisionedConcurrencyConfig?: AWS_Lambda_Version____ProvisionedConcurrencyConfiguration;
  };
}

export interface AWS_SageMaker_NotebookInstance {
  Type: "AWS::SageMaker::NotebookInstance";
  Properties: {
    KmsKeyId?: string;
    VolumeSizeInGB?: number;
    AdditionalCodeRepositories?: Array<string>;
    DefaultCodeRepository?: string;
    DirectInternetAccess?: string;
    AcceleratorTypes?: Array<string>;
    SubnetId?: string;
    SecurityGroupIds?: Array<string>;
    RoleArn: string;
    RootAccess?: string;
    NotebookInstanceName?: string;
    InstanceType: string;
    LifecycleConfigName?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_DataBrew_Recipe {
  Type: "AWS::DataBrew::Recipe";
  Properties: {
    Description?: string;
    Name: string;
    Steps: Array<RecipeStep>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_WAFv2_WebACLAssociation {
  Type: "AWS::WAFv2::WebACLAssociation";
  Properties: {
    ResourceArn: string;
    WebACLArn: string;
  };
}

export interface AWS_ApiGateway_BasePathMapping {
  Type: "AWS::ApiGateway::BasePathMapping";
  Properties: {
    BasePath?: string;
    DomainName: string;
    RestApiId?: string;
    Stage?: string;
  };
}

export interface AWS_DataSync_Task {
  Type: "AWS::DataSync::Task";
  Properties: {
    Excludes?: Array<AWS_DataSync_Task____FilterRule>;
    Tags?: Array<Tag>;
    CloudWatchLogGroupArn?: string;
    DestinationLocationArn: string;
    Name?: string;
    Options?: Options;
    Schedule?: TaskSchedule;
    SourceLocationArn: string;
  };
}

export interface AWS_EMR_Studio {
  Type: "AWS::EMR::Studio";
  Properties: {
    AuthMode: string;
    DefaultS3Location: string;
    Description?: string;
    EngineSecurityGroupId: string;
    Name: string;
    ServiceRole: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
    UserRole: string;
    VpcId: string;
    WorkspaceSecurityGroupId: string;
  };
}

export interface AWS_Cognito_UserPool {
  Type: "AWS::Cognito::UserPool";
  Properties: {
    UserPoolTags?: any;
    Policies?: AWS_Cognito_UserPool____Policies;
    VerificationMessageTemplate?: VerificationMessageTemplate;
    MfaConfiguration?: string;
    Schema?: Array<SchemaAttribute>;
    AdminCreateUserConfig?: AdminCreateUserConfig;
    SmsAuthenticationMessage?: string;
    UsernameConfiguration?: UsernameConfiguration;
    UserPoolName?: string;
    SmsVerificationMessage?: string;
    UserPoolAddOns?: UserPoolAddOns;
    EmailConfiguration?: EmailConfiguration;
    SmsConfiguration?: SmsConfiguration;
    AliasAttributes?: Array<string>;
    EnabledMfas?: Array<string>;
    EmailVerificationSubject?: string;
    LambdaConfig?: AWS_Cognito_UserPool____LambdaConfig;
    UsernameAttributes?: Array<string>;
    AutoVerifiedAttributes?: Array<string>;
    DeviceConfiguration?: DeviceConfiguration;
    EmailVerificationMessage?: string;
    AccountRecoverySetting?: AccountRecoverySetting;
  };
}

export interface AWS_DataSync_LocationObjectStorage {
  Type: "AWS::DataSync::LocationObjectStorage";
  Properties: {
    AccessKey?: string;
    AgentArns: Array<string>;
    BucketName: string;
    SecretKey?: string;
    ServerHostname: string;
    ServerPort?: number;
    ServerProtocol?: string;
    Subdirectory?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_EgressOnlyInternetGateway {
  Type: "AWS::EC2::EgressOnlyInternetGateway";
  Properties: {
    VpcId: string;
  };
}

export interface AWS_DataBrew_Project {
  Type: "AWS::DataBrew::Project";
  Properties: {
    DatasetName: string;
    Name: string;
    RecipeName: string;
    RoleArn: string;
    Sample?: Sample;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Events_ApiDestination {
  Type: "AWS::Events::ApiDestination";
  Properties: {
    Name?: string;
    Description?: string;
    ConnectionArn: string;
    InvocationRateLimitPerSecond?: number;
    InvocationEndpoint: string;
    HttpMethod: string;
  };
}

export interface AWS_ApiGatewayV2_Api {
  Type: "AWS::ApiGatewayV2::Api";
  Properties: {
    RouteSelectionExpression?: string;
    BodyS3Location?: BodyS3Location;
    Description?: string;
    BasePath?: string;
    FailOnWarnings?: boolean;
    DisableExecuteApiEndpoint?: boolean;
    DisableSchemaValidation?: boolean;
    Name?: string;
    Target?: string;
    CredentialsArn?: string;
    CorsConfiguration?: Cors;
    Version?: string;
    ProtocolType?: string;
    RouteKey?: string;
    Body?: any;
    Tags?: any;
    ApiKeySelectionExpression?: string;
  };
}

export interface AWS_DLM_LifecyclePolicy {
  Type: "AWS::DLM::LifecyclePolicy";
  Properties: {
    ExecutionRoleArn?: string;
    Description?: string;
    State?: string;
    PolicyDetails?: PolicyDetails;
    Tags?: Array<Tag>;
  };
}

export interface AWS_RDS_DBInstance {
  Type: "AWS::RDS::DBInstance";
  Properties: {
    AllocatedStorage?: string;
    AllowMajorVersionUpgrade?: boolean;
    AssociatedRoles?: Array<DBInstanceRole>;
    AutoMinorVersionUpgrade?: boolean;
    AvailabilityZone?: string;
    BackupRetentionPeriod?: number;
    CACertificateIdentifier?: string;
    CharacterSetName?: string;
    CopyTagsToSnapshot?: boolean;
    DBClusterIdentifier?: string;
    DBInstanceClass: string;
    DBInstanceIdentifier?: string;
    DBName?: string;
    DBParameterGroupName?: string;
    DBSecurityGroups?: Array<string>;
    DBSnapshotIdentifier?: string;
    DBSubnetGroupName?: string;
    DeleteAutomatedBackups?: boolean;
    DeletionProtection?: boolean;
    Domain?: string;
    DomainIAMRoleName?: string;
    EnableCloudwatchLogsExports?: Array<string>;
    EnableIAMDatabaseAuthentication?: boolean;
    EnablePerformanceInsights?: boolean;
    Engine?: string;
    EngineVersion?: string;
    Iops?: number;
    KmsKeyId?: string;
    LicenseModel?: string;
    MasterUserPassword?: string;
    MasterUsername?: string;
    MaxAllocatedStorage?: number;
    MonitoringInterval?: number;
    MonitoringRoleArn?: string;
    MultiAZ?: boolean;
    OptionGroupName?: string;
    PerformanceInsightsKMSKeyId?: string;
    PerformanceInsightsRetentionPeriod?: number;
    Port?: string;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    ProcessorFeatures?: Array<ProcessorFeature>;
    PromotionTier?: number;
    PubliclyAccessible?: boolean;
    SourceDBInstanceIdentifier?: string;
    SourceRegion?: string;
    StorageEncrypted?: boolean;
    StorageType?: string;
    Tags?: Array<Tag>;
    Timezone?: string;
    UseDefaultProcessorFeatures?: boolean;
    VPCSecurityGroups?: Array<string>;
  };
}

export interface AWS_EC2_NetworkInterfaceAttachment {
  Type: "AWS::EC2::NetworkInterfaceAttachment";
  Properties: {
    DeleteOnTermination?: boolean;
    DeviceIndex: string;
    InstanceId: string;
    NetworkInterfaceId: string;
  };
}

export interface AWS_WAFRegional_IPSet {
  Type: "AWS::WAFRegional::IPSet";
  Properties: {
    IPSetDescriptors?: Array<AWS_WAFRegional_IPSet____IPSetDescriptor>;
    Name: string;
  };
}

export interface AWS_RoboMaker_RobotApplication {
  Type: "AWS::RoboMaker::RobotApplication";
  Properties: {
    CurrentRevisionId?: string;
    RobotSoftwareSuite: AWS_RoboMaker_RobotApplication____RobotSoftwareSuite;
    Sources: Array<AWS_RoboMaker_RobotApplication____SourceConfig>;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_EC2_CustomerGateway {
  Type: "AWS::EC2::CustomerGateway";
  Properties: {
    BgpAsn: number;
    IpAddress: string;
    Tags?: Array<Tag>;
    Type: string;
  };
}

export interface AWS_ServiceDiscovery_HttpNamespace {
  Type: "AWS::ServiceDiscovery::HttpNamespace";
  Properties: {
    Description?: string;
    Tags?: Array<Tag>;
    Name: string;
  };
}

export interface AWS_SageMaker_CodeRepository {
  Type: "AWS::SageMaker::CodeRepository";
  Properties: {
    CodeRepositoryName?: string;
    GitConfig: GitConfig;
  };
}

export interface AWS_ApiGateway_Stage {
  Type: "AWS::ApiGateway::Stage";
  Properties: {
    AccessLogSetting?: AWS_ApiGateway_Stage____AccessLogSetting;
    CacheClusterEnabled?: boolean;
    CacheClusterSize?: string;
    CanarySetting?: AWS_ApiGateway_Stage____CanarySetting;
    ClientCertificateId?: string;
    DeploymentId?: string;
    Description?: string;
    DocumentationVersion?: string;
    MethodSettings?: Array<AWS_ApiGateway_Stage____MethodSetting>;
    RestApiId: string;
    StageName?: string;
    Tags?: Array<Tag>;
    TracingEnabled?: boolean;
    Variables?: Record<string, string>;
  };
}

export interface AWS_SDB_Domain {
  Type: "AWS::SDB::Domain";
  Properties: {
    Description?: string;
  };
}

export interface AWS_Cognito_UserPoolClient {
  Type: "AWS::Cognito::UserPoolClient";
  Properties: {
    AnalyticsConfiguration?: AWS_Cognito_UserPoolClient____AnalyticsConfiguration;
    GenerateSecret?: boolean;
    CallbackURLs?: Array<string>;
    IdTokenValidity?: number;
    AllowedOAuthScopes?: Array<string>;
    TokenValidityUnits?: TokenValidityUnits;
    ReadAttributes?: Array<string>;
    AllowedOAuthFlowsUserPoolClient?: boolean;
    DefaultRedirectURI?: string;
    SupportedIdentityProviders?: Array<string>;
    ClientName?: string;
    UserPoolId: string;
    AllowedOAuthFlows?: Array<string>;
    ExplicitAuthFlows?: Array<string>;
    LogoutURLs?: Array<string>;
    AccessTokenValidity?: number;
    RefreshTokenValidity?: number;
    WriteAttributes?: Array<string>;
    PreventUserExistenceErrors?: string;
  };
}

export interface AWS_CloudFormation_ResourceDefaultVersion {
  Type: "AWS::CloudFormation::ResourceDefaultVersion";
  Properties: {
    TypeVersionArn?: string;
    TypeName?: string;
    VersionId?: string;
  };
}

export interface AWS_IoTEvents_Input {
  Type: "AWS::IoTEvents::Input";
  Properties: {
    InputDefinition: InputDefinition;
    InputDescription?: string;
    InputName?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_FraudDetector_EventType {
  Type: "AWS::FraudDetector::EventType";
  Properties: {
    Name: string;
    Tags?: Array<Tag>;
    Description?: string;
    EventVariables: Array<AWS_FraudDetector_EventType____EventVariable>;
    Labels: Array<AWS_FraudDetector_EventType____Label>;
    EntityTypes: Array<AWS_FraudDetector_EventType____EntityType>;
  };
}

export interface AWS_ECR_Repository {
  Type: "AWS::ECR::Repository";
  Properties: {
    LifecyclePolicy?: AWS_ECR_Repository____LifecyclePolicy;
    RepositoryName?: string;
    RepositoryPolicyText?: any;
    Tags?: Array<Tag>;
    ImageTagMutability?: string;
    ImageScanningConfiguration?: any;
    EncryptionConfiguration?: any;
  };
}

export interface AWS_ApiGateway_GatewayResponse {
  Type: "AWS::ApiGateway::GatewayResponse";
  Properties: {
    ResponseParameters?: Record<string, string>;
    ResponseTemplates?: Record<string, string>;
    ResponseType: string;
    RestApiId: string;
    StatusCode?: string;
  };
}

export interface AWS_EC2_NetworkInsightsPath {
  Type: "AWS::EC2::NetworkInsightsPath";
  Properties: {
    SourceIp?: string;
    DestinationIp?: string;
    Source: string;
    Destination: string;
    Protocol: string;
    DestinationPort?: number;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Glue_Database {
  Type: "AWS::Glue::Database";
  Properties: {
    DatabaseInput: DatabaseInput;
    CatalogId: string;
  };
}

export interface AWS_ApiGatewayV2_RouteResponse {
  Type: "AWS::ApiGatewayV2::RouteResponse";
  Properties: {
    RouteResponseKey: string;
    ResponseParameters?: any;
    RouteId: string;
    ModelSelectionExpression?: string;
    ApiId: string;
    ResponseModels?: any;
  };
}

export interface AWS_ApiGateway_ClientCertificate {
  Type: "AWS::ApiGateway::ClientCertificate";
  Properties: {
    Description?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_IAM_OIDCProvider {
  Type: "AWS::IAM::OIDCProvider";
  Properties: {
    ClientIdList?: Array<string>;
    Url?: string;
    ThumbprintList: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Greengrass_LoggerDefinitionVersion {
  Type: "AWS::Greengrass::LoggerDefinitionVersion";
  Properties: {
    LoggerDefinitionId: string;
    Loggers: Array<AWS_Greengrass_LoggerDefinitionVersion____Logger>;
  };
}

export interface AWS_Lambda_CodeSigningConfig {
  Type: "AWS::Lambda::CodeSigningConfig";
  Properties: {
    Description?: string;
    AllowedPublishers: AllowedPublishers;
    CodeSigningPolicies?: CodeSigningPolicies;
  };
}

export interface AWS_RDS_DBSecurityGroup {
  Type: "AWS::RDS::DBSecurityGroup";
  Properties: {
    DBSecurityGroupIngress: Array<AWS_RDS_DBSecurityGroup____Ingress>;
    EC2VpcId?: string;
    GroupDescription: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_KMS_Alias {
  Type: "AWS::KMS::Alias";
  Properties: {
    AliasName: string;
    TargetKeyId: string;
  };
}

export interface AWS_QuickSight_Analysis {
  Type: "AWS::QuickSight::Analysis";
  Properties: {
    AnalysisId: string;
    AwsAccountId: string;
    Errors?: Array<AnalysisError>;
    Name?: string;
    Parameters?: AWS_QuickSight_Analysis____Parameters;
    Permissions?: Array<AWS_QuickSight_Analysis____ResourcePermission>;
    SourceEntity?: AnalysisSourceEntity;
    Tags?: Array<Tag>;
    ThemeArn?: string;
  };
}

export interface AWS_Redshift_ClusterSubnetGroup {
  Type: "AWS::Redshift::ClusterSubnetGroup";
  Properties: {
    Description: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_EIPAssociation {
  Type: "AWS::EC2::EIPAssociation";
  Properties: {
    AllocationId?: string;
    EIP?: string;
    InstanceId?: string;
    NetworkInterfaceId?: string;
    PrivateIpAddress?: string;
  };
}

export interface AWS_EC2_VPNGateway {
  Type: "AWS::EC2::VPNGateway";
  Properties: {
    AmazonSideAsn?: number;
    Tags?: Array<Tag>;
    Type: string;
  };
}

export interface AWS_GuardDuty_Detector {
  Type: "AWS::GuardDuty::Detector";
  Properties: {
    FindingPublishingFrequency?: string;
    DataSources?: CFNDataSourceConfigurations;
    Enable: boolean;
  };
}

export interface AWS_ServiceDiscovery_PrivateDnsNamespace {
  Type: "AWS::ServiceDiscovery::PrivateDnsNamespace";
  Properties: {
    Description?: string;
    Vpc: string;
    Tags?: Array<Tag>;
    Name: string;
  };
}

export interface AWS_IoT_Authorizer {
  Type: "AWS::IoT::Authorizer";
  Properties: {
    AuthorizerFunctionArn: string;
    AuthorizerName?: string;
    SigningDisabled?: boolean;
    Status?: string;
    TokenKeyName?: string;
    TokenSigningPublicKeys?: Record<string, string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_IAM_VirtualMFADevice {
  Type: "AWS::IAM::VirtualMFADevice";
  Properties: {
    VirtualMfaDeviceName?: string;
    Path?: string;
    Users: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Glue_DevEndpoint {
  Type: "AWS::Glue::DevEndpoint";
  Properties: {
    ExtraJarsS3Path?: string;
    PublicKey?: string;
    NumberOfNodes?: number;
    Arguments?: any;
    SubnetId?: string;
    PublicKeys?: Array<string>;
    SecurityGroupIds?: Array<string>;
    RoleArn: string;
    WorkerType?: string;
    EndpointName?: string;
    GlueVersion?: string;
    ExtraPythonLibsS3Path?: string;
    SecurityConfiguration?: string;
    NumberOfWorkers?: number;
    Tags?: any;
  };
}

export interface AWS_S3Outposts_AccessPoint {
  Type: "AWS::S3Outposts::AccessPoint";
  Properties: {
    Bucket: string;
    Name: string;
    VpcConfiguration: AWS_S3Outposts_AccessPoint____VpcConfiguration;
    Policy?: any;
  };
}

export interface AWS_CodeBuild_ReportGroup {
  Type: "AWS::CodeBuild::ReportGroup";
  Properties: {
    Type: string;
    ExportConfig: ReportExportConfig;
    DeleteReports?: boolean;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_OpsWorks_UserProfile {
  Type: "AWS::OpsWorks::UserProfile";
  Properties: {
    AllowSelfManagement?: boolean;
    IamUserArn: string;
    SshPublicKey?: string;
    SshUsername?: string;
  };
}

export interface AWS_Neptune_DBSubnetGroup {
  Type: "AWS::Neptune::DBSubnetGroup";
  Properties: {
    DBSubnetGroupName?: string;
    DBSubnetGroupDescription: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_FraudDetector_Detector {
  Type: "AWS::FraudDetector::Detector";
  Properties: {
    DetectorId: string;
    DetectorVersionStatus?: string;
    RuleExecutionMode?: string;
    Tags?: Array<Tag>;
    Description?: string;
    Rules: Array<AWS_FraudDetector_Detector____Rule>;
    EventType: EventType;
  };
}

export interface AWS_EC2_VPNConnection {
  Type: "AWS::EC2::VPNConnection";
  Properties: {
    CustomerGatewayId: string;
    StaticRoutesOnly?: boolean;
    Tags?: Array<Tag>;
    TransitGatewayId?: string;
    Type: string;
    VpnGatewayId?: string;
    VpnTunnelOptionsSpecifications?: Array<VpnTunnelOptionsSpecification>;
  };
}

export interface AWS_KinesisAnalyticsV2_Application {
  Type: "AWS::KinesisAnalyticsV2::Application";
  Properties: {
    ApplicationName?: string;
    RuntimeEnvironment: string;
    ApplicationConfiguration?: ApplicationConfiguration;
    ApplicationDescription?: string;
    Tags?: Array<Tag>;
    ServiceExecutionRole: string;
  };
}

export interface AWS_Route53Resolver_ResolverQueryLoggingConfigAssociation {
  Type: "AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation";
  Properties: {
    ResolverQueryLogConfigId?: string;
    ResourceId?: string;
  };
}

export interface AWS_GlobalAccelerator_Listener {
  Type: "AWS::GlobalAccelerator::Listener";
  Properties: {
    AcceleratorArn: string;
    PortRanges: Array<AWS_GlobalAccelerator_Listener____PortRange>;
    Protocol: string;
    ClientAffinity?: string;
  };
}

export interface AWS_FMS_NotificationChannel {
  Type: "AWS::FMS::NotificationChannel";
  Properties: {
    SnsRoleName: string;
    SnsTopicArn: string;
  };
}

export interface AWS_ServiceCatalogAppRegistry_ResourceAssociation {
  Type: "AWS::ServiceCatalogAppRegistry::ResourceAssociation";
  Properties: {
    Application: string;
    Resource: string;
    ResourceType: string;
  };
}

export interface AWS_Logs_SubscriptionFilter {
  Type: "AWS::Logs::SubscriptionFilter";
  Properties: {
    DestinationArn: string;
    FilterPattern: string;
    LogGroupName: string;
    RoleArn?: string;
  };
}

export interface AWS_Greengrass_FunctionDefinitionVersion {
  Type: "AWS::Greengrass::FunctionDefinitionVersion";
  Properties: {
    DefaultConfig?: AWS_Greengrass_FunctionDefinitionVersion____DefaultConfig;
    Functions: Array<AWS_Greengrass_FunctionDefinitionVersion____Function>;
    FunctionDefinitionId: string;
  };
}

export interface AWS_EventSchemas_RegistryPolicy {
  Type: "AWS::EventSchemas::RegistryPolicy";
  Properties: {
    Policy: any;
    RegistryName: string;
    RevisionId?: string;
  };
}

export interface AWS_AmazonMQ_Configuration {
  Type: "AWS::AmazonMQ::Configuration";
  Properties: {
    EngineVersion: string;
    Description?: string;
    AuthenticationStrategy?: string;
    EngineType: string;
    Data: string;
    Tags?: Array<AWS_AmazonMQ_Configuration____TagsEntry>;
    Name: string;
  };
}

export interface AWS_Logs_Destination {
  Type: "AWS::Logs::Destination";
  Properties: {
    DestinationName: string;
    DestinationPolicy: string;
    RoleArn: string;
    TargetArn: string;
  };
}

export interface AWS_Redshift_ClusterSecurityGroup {
  Type: "AWS::Redshift::ClusterSecurityGroup";
  Properties: {
    Description: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_TransitGatewayRouteTable {
  Type: "AWS::EC2::TransitGatewayRouteTable";
  Properties: {
    TransitGatewayId: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_WAF_XssMatchSet {
  Type: "AWS::WAF::XssMatchSet";
  Properties: {
    Name: string;
    XssMatchTuples: Array<AWS_WAF_XssMatchSet____XssMatchTuple>;
  };
}

export interface AWS_CloudFront_RealtimeLogConfig {
  Type: "AWS::CloudFront::RealtimeLogConfig";
  Properties: {
    EndPoints: Array<EndPoint>;
    Fields: Array<string>;
    Name: string;
    SamplingRate: number;
  };
}

export interface AWS_Route53_HealthCheck {
  Type: "AWS::Route53::HealthCheck";
  Properties: {
    HealthCheckConfig: any;
    HealthCheckTags?: Array<HealthCheckTag>;
  };
}

export interface AWS_S3Outposts_Bucket {
  Type: "AWS::S3Outposts::Bucket";
  Properties: {
    BucketName: string;
    OutpostId: string;
    Tags?: Array<Tag>;
    LifecycleConfiguration?: AWS_S3Outposts_Bucket____LifecycleConfiguration;
  };
}

export interface AWS_NetworkManager_Device {
  Type: "AWS::NetworkManager::Device";
  Properties: {
    Description?: string;
    Tags?: Array<Tag>;
    GlobalNetworkId: string;
    Location?: AWS_NetworkManager_Device____Location;
    Model?: string;
    SerialNumber?: string;
    SiteId?: string;
    Type?: string;
    Vendor?: string;
  };
}

export interface AWS_Neptune_DBInstance {
  Type: "AWS::Neptune::DBInstance";
  Properties: {
    DBParameterGroupName?: string;
    DBInstanceClass: string;
    AllowMajorVersionUpgrade?: boolean;
    DBClusterIdentifier?: string;
    AvailabilityZone?: string;
    PreferredMaintenanceWindow?: string;
    AutoMinorVersionUpgrade?: boolean;
    DBSubnetGroupName?: string;
    DBInstanceIdentifier?: string;
    DBSnapshotIdentifier?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_RDS_DBClusterParameterGroup {
  Type: "AWS::RDS::DBClusterParameterGroup";
  Properties: {
    Description: string;
    Family: string;
    Parameters: any;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Glue_SchemaVersionMetadata {
  Type: "AWS::Glue::SchemaVersionMetadata";
  Properties: {
    SchemaVersionId: string;
    Key: string;
    Value: string;
  };
}

export interface AWS_EC2_VPCEndpointService {
  Type: "AWS::EC2::VPCEndpointService";
  Properties: {
    NetworkLoadBalancerArns?: Array<string>;
    AcceptanceRequired?: boolean;
    GatewayLoadBalancerArns?: Array<string>;
  };
}

export interface AWS_Kinesis_StreamConsumer {
  Type: "AWS::Kinesis::StreamConsumer";
  Properties: {
    ConsumerName: string;
    StreamARN: string;
  };
}

export interface AWS_NetworkFirewall_FirewallPolicy {
  Type: "AWS::NetworkFirewall::FirewallPolicy";
  Properties: {
    FirewallPolicyName: string;
    FirewallPolicy: FirewallPolicy;
    Description?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_GuardDuty_Master {
  Type: "AWS::GuardDuty::Master";
  Properties: {
    DetectorId: string;
    MasterId: string;
    InvitationId?: string;
  };
}

export interface AWS_S3_BucketPolicy {
  Type: "AWS::S3::BucketPolicy";
  Properties: {
    Bucket: string;
    PolicyDocument: any;
  };
}

export interface AWS_CloudFormation_CustomResource {
  Type: "AWS::CloudFormation::CustomResource";
  Properties: {
    ServiceToken: string;
  };
}

export interface AWS_ServiceCatalog_StackSetConstraint {
  Type: "AWS::ServiceCatalog::StackSetConstraint";
  Properties: {
    Description: string;
    StackInstanceControl: string;
    AcceptLanguage?: string;
    PortfolioId: string;
    ProductId: string;
    RegionList: Array<string>;
    AdminRole: string;
    AccountList: Array<string>;
    ExecutionRole: string;
  };
}

export interface AWS_Glue_Crawler {
  Type: "AWS::Glue::Crawler";
  Properties: {
    Role: string;
    Classifiers?: Array<string>;
    Description?: string;
    SchemaChangePolicy?: SchemaChangePolicy;
    Configuration?: string;
    Schedule?: AWS_Glue_Crawler____Schedule;
    DatabaseName?: string;
    Targets: AWS_Glue_Crawler____Targets;
    CrawlerSecurityConfiguration?: string;
    TablePrefix?: string;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_EC2_ClientVpnRoute {
  Type: "AWS::EC2::ClientVpnRoute";
  Properties: {
    ClientVpnEndpointId: string;
    TargetVpcSubnetId: string;
    Description?: string;
    DestinationCidrBlock: string;
  };
}

export interface AWS_ApiGateway_DocumentationVersion {
  Type: "AWS::ApiGateway::DocumentationVersion";
  Properties: {
    Description?: string;
    DocumentationVersion: string;
    RestApiId: string;
  };
}

export interface AWS_MediaConnect_FlowOutput {
  Type: "AWS::MediaConnect::FlowOutput";
  Properties: {
    FlowArn: string;
    CidrAllowList?: Array<string>;
    Description?: string;
    Destination?: string;
    Encryption?: AWS_MediaConnect_FlowOutput____Encryption;
    MaxLatency?: number;
    Name?: string;
    Port?: number;
    Protocol: string;
    RemoteId?: string;
    SmoothingLatency?: number;
    StreamId?: string;
    VpcInterfaceAttachment?: VpcInterfaceAttachment;
  };
}

export interface AWS_SSM_MaintenanceWindowTask {
  Type: "AWS::SSM::MaintenanceWindowTask";
  Properties: {
    MaxErrors?: string;
    Description?: string;
    ServiceRoleArn?: string;
    Priority: number;
    MaxConcurrency?: string;
    Targets?: Array<AWS_SSM_MaintenanceWindowTask____Target>;
    Name?: string;
    TaskArn: string;
    TaskInvocationParameters?: TaskInvocationParameters;
    WindowId: string;
    TaskParameters?: any;
    TaskType: string;
    LoggingInfo?: AWS_SSM_MaintenanceWindowTask____LoggingInfo;
  };
}

export interface AWS_ServiceCatalog_ServiceAction {
  Type: "AWS::ServiceCatalog::ServiceAction";
  Properties: {
    AcceptLanguage?: string;
    Name: string;
    DefinitionType: string;
    Definition: Array<DefinitionParameter>;
    Description?: string;
  };
}

export interface AWS_Glue_MLTransform {
  Type: "AWS::Glue::MLTransform";
  Properties: {
    MaxRetries?: number;
    Description?: string;
    TransformEncryption?: TransformEncryption;
    Timeout?: number;
    Name?: string;
    Role: string;
    WorkerType?: string;
    GlueVersion?: string;
    TransformParameters: TransformParameters;
    InputRecordTables: InputRecordTables;
    NumberOfWorkers?: number;
    Tags?: any;
    MaxCapacity?: number;
  };
}

export interface AWS_Transfer_Server {
  Type: "AWS::Transfer::Server";
  Properties: {
    LoggingRole?: string;
    Protocols?: Array<Protocol>;
    IdentityProviderDetails?: IdentityProviderDetails;
    EndpointType?: string;
    SecurityPolicyName?: string;
    Domain?: string;
    EndpointDetails?: AWS_Transfer_Server____EndpointDetails;
    IdentityProviderType?: string;
    Tags?: Array<Tag>;
    Certificate?: string;
  };
}

export interface AWS_ApiGateway_UsagePlanKey {
  Type: "AWS::ApiGateway::UsagePlanKey";
  Properties: {
    KeyId: string;
    KeyType: string;
    UsagePlanId: string;
  };
}

export interface AWS_EMR_SecurityConfiguration {
  Type: "AWS::EMR::SecurityConfiguration";
  Properties: {
    Name?: string;
    SecurityConfiguration: any;
  };
}

export interface AWS_CodeGuruReviewer_RepositoryAssociation {
  Type: "AWS::CodeGuruReviewer::RepositoryAssociation";
  Properties: {
    Name: string;
    Type: string;
    Owner?: string;
    ConnectionArn?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Cognito_UserPoolUserToGroupAttachment {
  Type: "AWS::Cognito::UserPoolUserToGroupAttachment";
  Properties: {
    GroupName: string;
    UserPoolId: string;
    Username: string;
  };
}

export interface AWS_Glue_Classifier {
  Type: "AWS::Glue::Classifier";
  Properties: {
    XMLClassifier?: XMLClassifier;
    JsonClassifier?: JsonClassifier;
    CsvClassifier?: CsvClassifier;
    GrokClassifier?: GrokClassifier;
  };
}

export interface AWS_RoboMaker_Fleet {
  Type: "AWS::RoboMaker::Fleet";
  Properties: {
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_AmazonMQ_Broker {
  Type: "AWS::AmazonMQ::Broker";
  Properties: {
    SecurityGroups?: Array<string>;
    StorageType?: string;
    EngineVersion: string;
    Configuration?: AWS_AmazonMQ_Broker____ConfigurationId;
    AuthenticationStrategy?: string;
    MaintenanceWindowStartTime?: MaintenanceWindow;
    HostInstanceType: string;
    AutoMinorVersionUpgrade: boolean;
    Users: Array<User>;
    Logs?: LogList;
    SubnetIds?: Array<string>;
    BrokerName: string;
    LdapServerMetadata?: LdapServerMetadata;
    DeploymentMode: string;
    EngineType: string;
    PubliclyAccessible: boolean;
    EncryptionOptions?: EncryptionOptions;
    Tags?: Array<AWS_AmazonMQ_Broker____TagsEntry>;
  };
}

export interface AWS_ElasticBeanstalk_ConfigurationTemplate {
  Type: "AWS::ElasticBeanstalk::ConfigurationTemplate";
  Properties: {
    ApplicationName: string;
    Description?: string;
    EnvironmentId?: string;
    OptionSettings?: Array<ConfigurationOptionSetting>;
    PlatformArn?: string;
    SolutionStackName?: string;
    SourceConfiguration?: SourceConfiguration;
  };
}

export interface AWS_ServiceCatalogAppRegistry_AttributeGroup {
  Type: "AWS::ServiceCatalogAppRegistry::AttributeGroup";
  Properties: {
    Name: string;
    Description?: string;
    Attributes: any;
    Tags?: Record<string, string>;
  };
}

export interface AWS_AppSync_DataSource {
  Type: "AWS::AppSync::DataSource";
  Properties: {
    Type: string;
    Description?: string;
    ServiceRoleArn?: string;
    HttpConfig?: HttpConfig;
    RelationalDatabaseConfig?: RelationalDatabaseConfig;
    LambdaConfig?: AWS_AppSync_DataSource____LambdaConfig;
    ApiId: string;
    Name: string;
    DynamoDBConfig?: DynamoDBConfig;
    ElasticsearchConfig?: ElasticsearchConfig;
  };
}

export interface AWS_ECS_PrimaryTaskSet {
  Type: "AWS::ECS::PrimaryTaskSet";
  Properties: {
    Cluster: string;
    TaskSetId: string;
    Service: string;
  };
}

export interface AWS_Greengrass_Group {
  Type: "AWS::Greengrass::Group";
  Properties: {
    InitialVersion?: GroupVersion;
    RoleArn?: string;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_Cognito_IdentityPoolRoleAttachment {
  Type: "AWS::Cognito::IdentityPoolRoleAttachment";
  Properties: {
    RoleMappings?: any;
    IdentityPoolId: string;
    Roles?: any;
  };
}

export interface AWS_Events_Rule {
  Type: "AWS::Events::Rule";
  Properties: {
    Description?: string;
    EventBusName?: string;
    EventPattern?: any;
    Name?: string;
    RoleArn?: string;
    ScheduleExpression?: string;
    State?: string;
    Targets?: Array<AWS_Events_Rule____Target>;
  };
}

export interface AWS_ImageBuilder_Component {
  Type: "AWS::ImageBuilder::Component";
  Properties: {
    Name: string;
    Version: string;
    Description?: string;
    ChangeDescription?: string;
    Platform: string;
    Data?: string;
    KmsKeyId?: string;
    Tags?: Record<string, string>;
    Uri?: string;
    SupportedOsVersions?: Array<string>;
  };
}

export interface AWS_CodePipeline_CustomActionType {
  Type: "AWS::CodePipeline::CustomActionType";
  Properties: {
    Category: string;
    ConfigurationProperties?: Array<ConfigurationProperties>;
    InputArtifactDetails: ArtifactDetails;
    OutputArtifactDetails: ArtifactDetails;
    Provider: string;
    Settings?: Settings;
    Tags?: Array<Tag>;
    Version: string;
  };
}

export interface AWS_AppMesh_VirtualNode {
  Type: "AWS::AppMesh::VirtualNode";
  Properties: {
    MeshName: string;
    MeshOwner?: string;
    Spec: VirtualNodeSpec;
    VirtualNodeName?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_AppMesh_VirtualRouter {
  Type: "AWS::AppMesh::VirtualRouter";
  Properties: {
    MeshName: string;
    VirtualRouterName?: string;
    MeshOwner?: string;
    Spec: VirtualRouterSpec;
    Tags?: Array<Tag>;
  };
}

export interface AWS_DataSync_Agent {
  Type: "AWS::DataSync::Agent";
  Properties: {
    AgentName?: string;
    ActivationKey: string;
    SecurityGroupArns?: Array<string>;
    SubnetArns?: Array<string>;
    VpcEndpointId?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Greengrass_ConnectorDefinition {
  Type: "AWS::Greengrass::ConnectorDefinition";
  Properties: {
    InitialVersion?: ConnectorDefinitionVersion;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_EC2_PlacementGroup {
  Type: "AWS::EC2::PlacementGroup";
  Properties: {
    Strategy?: string;
  };
}

export interface AWS_WAFRegional_SizeConstraintSet {
  Type: "AWS::WAFRegional::SizeConstraintSet";
  Properties: {
    SizeConstraints?: Array<AWS_WAFRegional_SizeConstraintSet____SizeConstraint>;
    Name: string;
  };
}

export interface AWS_ApiGateway_RequestValidator {
  Type: "AWS::ApiGateway::RequestValidator";
  Properties: {
    Name?: string;
    RestApiId: string;
    ValidateRequestBody?: boolean;
    ValidateRequestParameters?: boolean;
  };
}

export interface AWS_AppMesh_VirtualService {
  Type: "AWS::AppMesh::VirtualService";
  Properties: {
    MeshName: string;
    MeshOwner?: string;
    VirtualServiceName: string;
    Spec: VirtualServiceSpec;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Route53Resolver_ResolverDNSSECConfig {
  Type: "AWS::Route53Resolver::ResolverDNSSECConfig";
  Properties: {
    ResourceId?: string;
  };
}

export interface AWS_RDS_DBSecurityGroupIngress {
  Type: "AWS::RDS::DBSecurityGroupIngress";
  Properties: {
    CIDRIP?: string;
    DBSecurityGroupName: string;
    EC2SecurityGroupId?: string;
    EC2SecurityGroupName?: string;
    EC2SecurityGroupOwnerId?: string;
  };
}

export interface AWS_Timestream_Database {
  Type: "AWS::Timestream::Database";
  Properties: {
    DatabaseName?: string;
    KmsKeyId?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_GatewayRouteTableAssociation {
  Type: "AWS::EC2::GatewayRouteTableAssociation";
  Properties: {
    RouteTableId: string;
    GatewayId: string;
  };
}

export interface AWS_CodePipeline_Webhook {
  Type: "AWS::CodePipeline::Webhook";
  Properties: {
    AuthenticationConfiguration: WebhookAuthConfiguration;
    Filters: Array<WebhookFilterRule>;
    Authentication: string;
    TargetPipeline: string;
    TargetAction: string;
    Name?: string;
    TargetPipelineVersion: number;
    RegisterWithThirdParty?: boolean;
  };
}

export interface AWS_Logs_LogGroup {
  Type: "AWS::Logs::LogGroup";
  Properties: {
    LogGroupName?: string;
    KmsKeyId?: string;
    RetentionInDays?: number;
  };
}

export interface AWS_DataSync_LocationEFS {
  Type: "AWS::DataSync::LocationEFS";
  Properties: {
    Ec2Config: Ec2Config;
    EfsFilesystemArn: string;
    Subdirectory?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_AutoScalingPlans_ScalingPlan {
  Type: "AWS::AutoScalingPlans::ScalingPlan";
  Properties: {
    ApplicationSource: ApplicationSource;
    ScalingInstructions: Array<ScalingInstruction>;
  };
}

export interface AWS_CloudWatch_MetricStream {
  Type: "AWS::CloudWatch::MetricStream";
  Properties: {
    ExcludeFilters?: Array<MetricStreamFilter>;
    FirehoseArn: string;
    IncludeFilters?: Array<MetricStreamFilter>;
    Name?: string;
    RoleArn: string;
    OutputFormat: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ImageBuilder_InfrastructureConfiguration {
  Type: "AWS::ImageBuilder::InfrastructureConfiguration";
  Properties: {
    Name: string;
    Description?: string;
    InstanceTypes?: Array<string>;
    SecurityGroupIds?: Array<string>;
    Logging?: any;
    SubnetId?: string;
    KeyPair?: string;
    TerminateInstanceOnFailure?: boolean;
    InstanceProfileName: string;
    SnsTopicArn?: string;
    ResourceTags?: Record<string, string>;
    Tags?: Record<string, string>;
  };
}

export interface AWS_WAFRegional_XssMatchSet {
  Type: "AWS::WAFRegional::XssMatchSet";
  Properties: {
    XssMatchTuples?: Array<AWS_WAFRegional_XssMatchSet____XssMatchTuple>;
    Name: string;
  };
}

export interface AWS_EC2_NetworkAclEntry {
  Type: "AWS::EC2::NetworkAclEntry";
  Properties: {
    CidrBlock?: string;
    Egress?: boolean;
    Icmp?: Icmp;
    Ipv6CidrBlock?: string;
    NetworkAclId: string;
    PortRange?: AWS_EC2_NetworkAclEntry____PortRange;
    Protocol: number;
    RuleAction: string;
    RuleNumber: number;
  };
}

export interface AWS_EC2_InternetGateway {
  Type: "AWS::EC2::InternetGateway";
  Properties: {
    Tags?: Array<Tag>;
  };
}

export interface AWS_ElasticLoadBalancingV2_ListenerCertificate {
  Type: "AWS::ElasticLoadBalancingV2::ListenerCertificate";
  Properties: {
    Certificates: Array<AWS_ElasticLoadBalancingV2_ListenerCertificate____Certificate>;
    ListenerArn: string;
  };
}

export interface AWS_IAM_Role {
  Type: "AWS::IAM::Role";
  Properties: {
    AssumeRolePolicyDocument: any;
    Description?: string;
    ManagedPolicyArns?: Array<string>;
    MaxSessionDuration?: number;
    Path?: string;
    PermissionsBoundary?: string;
    Policies?: Array<AWS_IAM_Role____Policy>;
    RoleName?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Neptune_DBParameterGroup {
  Type: "AWS::Neptune::DBParameterGroup";
  Properties: {
    Description: string;
    Parameters: any;
    Family: string;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_Macie_FindingsFilter {
  Type: "AWS::Macie::FindingsFilter";
  Properties: {
    Name: string;
    Description?: string;
    FindingCriteria: AWS_Macie_FindingsFilter____FindingCriteria;
    Action?: string;
    Position?: number;
  };
}

export interface AWS_EKS_Addon {
  Type: "AWS::EKS::Addon";
  Properties: {
    ClusterName: string;
    AddonName: string;
    AddonVersion?: string;
    ResolveConflicts?: string;
    ServiceAccountRoleArn?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_LaunchTemplate {
  Type: "AWS::EC2::LaunchTemplate";
  Properties: {
    LaunchTemplateName?: string;
    LaunchTemplateData?: LaunchTemplateData;
    TagSpecifications?: Array<LaunchTemplateTagSpecification>;
  };
}

export interface AWS_Events_Archive {
  Type: "AWS::Events::Archive";
  Properties: {
    ArchiveName?: string;
    SourceArn: string;
    Description?: string;
    EventPattern?: any;
    RetentionDays?: number;
  };
}

export interface AWS_OpsWorks_Volume {
  Type: "AWS::OpsWorks::Volume";
  Properties: {
    Ec2VolumeId: string;
    MountPoint?: string;
    Name?: string;
    StackId: string;
  };
}

export interface AWS_IoT_Dimension {
  Type: "AWS::IoT::Dimension";
  Properties: {
    Name?: string;
    Type: string;
    StringValues: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ServiceCatalog_TagOptionAssociation {
  Type: "AWS::ServiceCatalog::TagOptionAssociation";
  Properties: {
    TagOptionId: string;
    ResourceId: string;
  };
}

export interface AWS_ACMPCA_Certificate {
  Type: "AWS::ACMPCA::Certificate";
  Properties: {
    ApiPassthrough?: ApiPassthrough;
    CertificateAuthorityArn: string;
    CertificateSigningRequest: string;
    SigningAlgorithm: string;
    TemplateArn?: string;
    Validity: Validity;
    ValidityNotBefore?: Validity;
  };
}

export interface AWS_QuickSight_Template {
  Type: "AWS::QuickSight::Template";
  Properties: {
    AwsAccountId: string;
    Name?: string;
    Permissions?: Array<AWS_QuickSight_Template____ResourcePermission>;
    SourceEntity?: TemplateSourceEntity;
    Tags?: Array<Tag>;
    TemplateId: string;
    VersionDescription?: string;
  };
}

export interface AWS_Glue_Schema {
  Type: "AWS::Glue::Schema";
  Properties: {
    Registry?: Registry;
    Name: string;
    Description?: string;
    DataFormat: string;
    Compatibility: string;
    SchemaDefinition: string;
    CheckpointVersion?: SchemaVersion;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SageMaker_AppImageConfig {
  Type: "AWS::SageMaker::AppImageConfig";
  Properties: {
    AppImageConfigName: string;
    KernelGatewayImageConfig?: KernelGatewayImageConfig;
    Tags?: Array<Tag>;
  };
}

export interface AWS_QuickSight_DataSource {
  Type: "AWS::QuickSight::DataSource";
  Properties: {
    AlternateDataSourceParameters?: Array<DataSourceParameters>;
    AwsAccountId?: string;
    Credentials?: DataSourceCredentials;
    DataSourceId?: string;
    DataSourceParameters?: DataSourceParameters;
    ErrorInfo?: DataSourceErrorInfo;
    Name?: string;
    Permissions?: Array<AWS_QuickSight_DataSource____ResourcePermission>;
    SslProperties?: SslProperties;
    Tags?: Array<Tag>;
    Type?: string;
    VpcConnectionProperties?: VpcConnectionProperties;
  };
}

export interface AWS_ServiceCatalog_LaunchTemplateConstraint {
  Type: "AWS::ServiceCatalog::LaunchTemplateConstraint";
  Properties: {
    Description?: string;
    AcceptLanguage?: string;
    PortfolioId: string;
    ProductId: string;
    Rules: string;
  };
}

export interface AWS_EMR_Cluster {
  Type: "AWS::EMR::Cluster";
  Properties: {
    AdditionalInfo?: any;
    Applications?: Array<Application>;
    AutoScalingRole?: string;
    BootstrapActions?: Array<BootstrapActionConfig>;
    Configurations?: Array<AWS_EMR_Cluster____Configuration>;
    CustomAmiId?: string;
    EbsRootVolumeSize?: number;
    Instances: JobFlowInstancesConfig;
    JobFlowRole: string;
    KerberosAttributes?: KerberosAttributes;
    LogEncryptionKmsKeyId?: string;
    LogUri?: string;
    ManagedScalingPolicy?: ManagedScalingPolicy;
    Name: string;
    ReleaseLabel?: string;
    ScaleDownBehavior?: string;
    SecurityConfiguration?: string;
    ServiceRole: string;
    StepConcurrencyLevel?: number;
    Steps?: Array<StepConfig>;
    Tags?: Array<Tag>;
    VisibleToAllUsers?: boolean;
  };
}

export interface AWS_SageMaker_Pipeline {
  Type: "AWS::SageMaker::Pipeline";
  Properties: {
    PipelineName: string;
    PipelineDisplayName?: string;
    PipelineDescription?: string;
    PipelineDefinition: any;
    RoleArn: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_SpotFleet {
  Type: "AWS::EC2::SpotFleet";
  Properties: {
    SpotFleetRequestConfigData: SpotFleetRequestConfigData;
  };
}

export interface AWS_S3ObjectLambda_AccessPointPolicy {
  Type: "AWS::S3ObjectLambda::AccessPointPolicy";
  Properties: {
    ObjectLambdaAccessPoint: string;
    PolicyDocument: any;
  };
}

export interface AWS_SSO_Assignment {
  Type: "AWS::SSO::Assignment";
  Properties: {
    InstanceArn: string;
    TargetId: string;
    TargetType: string;
    PermissionSetArn: string;
    PrincipalType: string;
    PrincipalId: string;
  };
}

export interface AWS_GameLift_Alias {
  Type: "AWS::GameLift::Alias";
  Properties: {
    Description?: string;
    Name: string;
    RoutingStrategy: RoutingStrategy;
  };
}

export interface AWS_EC2_VPNConnectionRoute {
  Type: "AWS::EC2::VPNConnectionRoute";
  Properties: {
    DestinationCidrBlock: string;
    VpnConnectionId: string;
  };
}

export interface AWS_DirectoryService_MicrosoftAD {
  Type: "AWS::DirectoryService::MicrosoftAD";
  Properties: {
    CreateAlias?: boolean;
    Edition?: string;
    EnableSso?: boolean;
    Name: string;
    Password: string;
    ShortName?: string;
    VpcSettings: AWS_DirectoryService_MicrosoftAD____VpcSettings;
  };
}

export interface AWS_WAF_Rule {
  Type: "AWS::WAF::Rule";
  Properties: {
    MetricName: string;
    Name: string;
    Predicates?: Array<AWS_WAF_Rule____Predicate>;
  };
}

export interface AWS_ApiGatewayV2_DomainName {
  Type: "AWS::ApiGatewayV2::DomainName";
  Properties: {
    MutualTlsAuthentication?: AWS_ApiGatewayV2_DomainName____MutualTlsAuthentication;
    DomainName: string;
    DomainNameConfigurations?: Array<DomainNameConfiguration>;
    Tags?: any;
  };
}

export interface AWS_Greengrass_FunctionDefinition {
  Type: "AWS::Greengrass::FunctionDefinition";
  Properties: {
    InitialVersion?: FunctionDefinitionVersion;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_SSM_Document {
  Type: "AWS::SSM::Document";
  Properties: {
    Content: any;
    Attachments?: Array<AttachmentsSource>;
    Name?: string;
    VersionName?: string;
    DocumentType?: string;
    DocumentFormat?: string;
    TargetType?: string;
    Tags?: Array<Tag>;
    Requires?: Array<DocumentRequires>;
  };
}

export interface AWS_EC2_NetworkInterfacePermission {
  Type: "AWS::EC2::NetworkInterfacePermission";
  Properties: {
    AwsAccountId: string;
    NetworkInterfaceId: string;
    Permission: string;
  };
}

export interface AWS_SageMaker_Model {
  Type: "AWS::SageMaker::Model";
  Properties: {
    ExecutionRoleArn: string;
    EnableNetworkIsolation?: boolean;
    PrimaryContainer?: AWS_SageMaker_Model____ContainerDefinition;
    ModelName?: string;
    VpcConfig?: AWS_SageMaker_Model____VpcConfig;
    Containers?: Array<AWS_SageMaker_Model____ContainerDefinition>;
    InferenceExecutionConfig?: InferenceExecutionConfig;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Config_DeliveryChannel {
  Type: "AWS::Config::DeliveryChannel";
  Properties: {
    ConfigSnapshotDeliveryProperties?: ConfigSnapshotDeliveryProperties;
    Name?: string;
    S3BucketName: string;
    S3KeyPrefix?: string;
    S3KmsKeyArn?: string;
    SnsTopicARN?: string;
  };
}

export interface AWS_GameLift_Build {
  Type: "AWS::GameLift::Build";
  Properties: {
    Name?: string;
    OperatingSystem?: string;
    StorageLocation?: AWS_GameLift_Build____S3Location;
    Version?: string;
  };
}

export interface AWS_EC2_TrafficMirrorFilter {
  Type: "AWS::EC2::TrafficMirrorFilter";
  Properties: {
    Description?: string;
    NetworkServices?: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Config_OrganizationConfigRule {
  Type: "AWS::Config::OrganizationConfigRule";
  Properties: {
    OrganizationManagedRuleMetadata?: OrganizationManagedRuleMetadata;
    OrganizationConfigRuleName: string;
    OrganizationCustomRuleMetadata?: OrganizationCustomRuleMetadata;
    ExcludedAccounts?: Array<string>;
  };
}

export interface AWS_ECR_ReplicationConfiguration {
  Type: "AWS::ECR::ReplicationConfiguration";
  Properties: {
    ReplicationConfiguration: AWS_ECR_ReplicationConfiguration____ReplicationConfiguration;
  };
}

export interface AWS_LicenseManager_License {
  Type: "AWS::LicenseManager::License";
  Properties: {
    ProductSKU?: string;
    Issuer: IssuerData;
    LicenseName: string;
    ProductName: string;
    HomeRegion: string;
    Validity: ValidityDateFormat;
    Entitlements: Array<Entitlement>;
    Beneficiary?: string;
    ConsumptionConfiguration: ConsumptionConfiguration;
    LicenseMetadata?: Array<Metadata>;
    Status?: string;
  };
}

export interface AWS_QLDB_Ledger {
  Type: "AWS::QLDB::Ledger";
  Properties: {
    PermissionsMode: string;
    DeletionProtection?: boolean;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_ApiGatewayV2_Integration {
  Type: "AWS::ApiGatewayV2::Integration";
  Properties: {
    Description?: string;
    TemplateSelectionExpression?: string;
    ConnectionType?: string;
    ResponseParameters?: any;
    IntegrationMethod?: string;
    PassthroughBehavior?: string;
    RequestParameters?: any;
    ConnectionId?: string;
    IntegrationUri?: string;
    PayloadFormatVersion?: string;
    CredentialsArn?: string;
    RequestTemplates?: any;
    TimeoutInMillis?: number;
    TlsConfig?: TlsConfig;
    ContentHandlingStrategy?: string;
    IntegrationSubtype?: string;
    ApiId: string;
    IntegrationType: string;
  };
}

export interface AWS_Backup_BackupSelection {
  Type: "AWS::Backup::BackupSelection";
  Properties: {
    BackupPlanId: string;
    BackupSelection: BackupSelectionResourceType;
  };
}

export interface AWS_CloudWatch_Alarm {
  Type: "AWS::CloudWatch::Alarm";
  Properties: {
    ActionsEnabled?: boolean;
    AlarmActions?: Array<string>;
    AlarmDescription?: string;
    AlarmName?: string;
    ComparisonOperator: string;
    DatapointsToAlarm?: number;
    Dimensions?: Array<AWS_CloudWatch_Alarm____Dimension>;
    EvaluateLowSampleCountPercentile?: string;
    EvaluationPeriods: number;
    ExtendedStatistic?: string;
    InsufficientDataActions?: Array<string>;
    MetricName?: string;
    Metrics?: Array<MetricDataQuery>;
    Namespace?: string;
    OKActions?: Array<string>;
    Period?: number;
    Statistic?: string;
    Threshold?: number;
    ThresholdMetricId?: string;
    TreatMissingData?: string;
    Unit?: string;
  };
}

export interface AWS_Route53Resolver_FirewallDomainList {
  Type: "AWS::Route53Resolver::FirewallDomainList";
  Properties: {
    Name?: string;
    Domains?: Array<string>;
    DomainFileUrl?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CertificateManager_Certificate {
  Type: "AWS::CertificateManager::Certificate";
  Properties: {
    CertificateAuthorityArn?: string;
    CertificateTransparencyLoggingPreference?: string;
    DomainName: string;
    DomainValidationOptions?: Array<DomainValidationOption>;
    SubjectAlternativeNames?: Array<string>;
    Tags?: Array<Tag>;
    ValidationMethod?: string;
  };
}

export interface AWS_Greengrass_SubscriptionDefinitionVersion {
  Type: "AWS::Greengrass::SubscriptionDefinitionVersion";
  Properties: {
    SubscriptionDefinitionId: string;
    Subscriptions: Array<AWS_Greengrass_SubscriptionDefinitionVersion____Subscription>;
  };
}

export interface AWS_Greengrass_CoreDefinitionVersion {
  Type: "AWS::Greengrass::CoreDefinitionVersion";
  Properties: {
    Cores: Array<AWS_Greengrass_CoreDefinitionVersion____Core>;
    CoreDefinitionId: string;
  };
}

export interface AWS_MediaConvert_Preset {
  Type: "AWS::MediaConvert::Preset";
  Properties: {
    Category?: string;
    Description?: string;
    SettingsJson: any;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_LicenseManager_Grant {
  Type: "AWS::LicenseManager::Grant";
  Properties: {
    GrantName?: string;
    LicenseArn?: string;
    HomeRegion?: string;
    AllowedOperations?: Array<string>;
    Principals?: Array<string>;
    Status?: string;
  };
}

export interface AWS_IAM_SAMLProvider {
  Type: "AWS::IAM::SAMLProvider";
  Properties: {
    Name?: string;
    SamlMetadataDocument: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CodeStarNotifications_NotificationRule {
  Type: "AWS::CodeStarNotifications::NotificationRule";
  Properties: {
    EventTypeIds: Array<string>;
    Status?: string;
    DetailType: string;
    Resource: string;
    Targets: Array<AWS_CodeStarNotifications_NotificationRule____Target>;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_Inspector_ResourceGroup {
  Type: "AWS::Inspector::ResourceGroup";
  Properties: {
    ResourceGroupTags: Array<Tag>;
  };
}

export interface AWS_IoTAnalytics_Dataset {
  Type: "AWS::IoTAnalytics::Dataset";
  Properties: {
    Actions: Array<AWS_IoTAnalytics_Dataset____Action>;
    LateDataRules?: Array<LateDataRule>;
    DatasetName?: string;
    ContentDeliveryRules?: Array<DatasetContentDeliveryRule>;
    Triggers?: Array<Trigger>;
    VersioningConfiguration?: AWS_IoTAnalytics_Dataset____VersioningConfiguration;
    RetentionPeriod?: AWS_IoTAnalytics_Dataset____RetentionPeriod;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EMRContainers_VirtualCluster {
  Type: "AWS::EMRContainers::VirtualCluster";
  Properties: {
    ContainerProvider: ContainerProvider;
    Name: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_NetworkFirewall_Firewall {
  Type: "AWS::NetworkFirewall::Firewall";
  Properties: {
    FirewallName: string;
    FirewallPolicyArn: string;
    VpcId: string;
    SubnetMappings: Array<AWS_NetworkFirewall_Firewall____SubnetMapping>;
    DeleteProtection?: boolean;
    SubnetChangeProtection?: boolean;
    FirewallPolicyChangeProtection?: boolean;
    Description?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_FinSpace_Environment {
  Type: "AWS::FinSpace::Environment";
  Properties: {
    Name: string;
    Description?: string;
    KmsKeyId?: string;
    FederationMode?: string;
    FederationParameters?: FederationParameters;
  };
}

export interface AWS_XRay_SamplingRule {
  Type: "AWS::XRay::SamplingRule";
  Properties: {
    SamplingRule?: SamplingRule;
    SamplingRuleRecord?: SamplingRuleRecord;
    SamplingRuleUpdate?: SamplingRuleUpdate;
    RuleName?: string;
    Tags?: Array<any>;
  };
}

export interface AWS_IoT_ProvisioningTemplate {
  Type: "AWS::IoT::ProvisioningTemplate";
  Properties: {
    TemplateName?: string;
    Description?: string;
    Enabled?: boolean;
    ProvisioningRoleArn: string;
    TemplateBody: string;
    PreProvisioningHook?: ProvisioningHook;
    Tags?: Array<Tag>;
  };
}

export interface AWS_DocDB_DBSubnetGroup {
  Type: "AWS::DocDB::DBSubnetGroup";
  Properties: {
    DBSubnetGroupName?: string;
    DBSubnetGroupDescription: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ServiceCatalog_PortfolioPrincipalAssociation {
  Type: "AWS::ServiceCatalog::PortfolioPrincipalAssociation";
  Properties: {
    PrincipalARN: string;
    AcceptLanguage?: string;
    PortfolioId: string;
    PrincipalType: string;
  };
}

export interface AWS_DataBrew_Job {
  Type: "AWS::DataBrew::Job";
  Properties: {
    DatasetName?: string;
    EncryptionKeyArn?: string;
    EncryptionMode?: string;
    Name: string;
    Type: string;
    LogSubscription?: string;
    MaxCapacity?: number;
    MaxRetries?: number;
    Outputs?: Array<AWS_DataBrew_Job____Output>;
    OutputLocation?: OutputLocation;
    ProjectName?: string;
    Recipe?: any;
    RoleArn: string;
    Tags?: Array<Tag>;
    Timeout?: number;
    JobSample?: JobSample;
  };
}

export interface AWS_GameLift_MatchmakingRuleSet {
  Type: "AWS::GameLift::MatchmakingRuleSet";
  Properties: {
    RuleSetBody: string;
    Name: string;
  };
}

export interface AWS_ImageBuilder_ImagePipeline {
  Type: "AWS::ImageBuilder::ImagePipeline";
  Properties: {
    Name: string;
    Description?: string;
    ImageTestsConfiguration?: AWS_ImageBuilder_ImagePipeline____ImageTestsConfiguration;
    Status?: string;
    Schedule?: AWS_ImageBuilder_ImagePipeline____Schedule;
    ImageRecipeArn?: string;
    ContainerRecipeArn?: string;
    DistributionConfigurationArn?: string;
    InfrastructureConfigurationArn: string;
    EnhancedImageMetadataEnabled?: boolean;
    Tags?: Record<string, string>;
  };
}

export interface AWS_EC2_SecurityGroupIngress {
  Type: "AWS::EC2::SecurityGroupIngress";
  Properties: {
    CidrIp?: string;
    CidrIpv6?: string;
    Description?: string;
    FromPort?: number;
    GroupId?: string;
    GroupName?: string;
    IpProtocol: string;
    SourcePrefixListId?: string;
    SourceSecurityGroupId?: string;
    SourceSecurityGroupName?: string;
    SourceSecurityGroupOwnerId?: string;
    ToPort?: number;
  };
}

export interface AWS_EC2_TransitGatewayMulticastGroupMember {
  Type: "AWS::EC2::TransitGatewayMulticastGroupMember";
  Properties: {
    GroupIpAddress: string;
    TransitGatewayMulticastDomainId: string;
    NetworkInterfaceId: string;
  };
}

export interface AWS_RDS_DBCluster {
  Type: "AWS::RDS::DBCluster";
  Properties: {
    AssociatedRoles?: Array<AWS_RDS_DBCluster____DBClusterRole>;
    AvailabilityZones?: Array<string>;
    BacktrackWindow?: number;
    BackupRetentionPeriod?: number;
    DBClusterIdentifier?: string;
    DBClusterParameterGroupName?: string;
    DBSubnetGroupName?: string;
    DatabaseName?: string;
    DeletionProtection?: boolean;
    EnableCloudwatchLogsExports?: Array<string>;
    EnableHttpEndpoint?: boolean;
    EnableIAMDatabaseAuthentication?: boolean;
    Engine: string;
    EngineMode?: string;
    EngineVersion?: string;
    GlobalClusterIdentifier?: string;
    KmsKeyId?: string;
    MasterUserPassword?: string;
    MasterUsername?: string;
    Port?: number;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    ReplicationSourceIdentifier?: string;
    RestoreType?: string;
    ScalingConfiguration?: ScalingConfiguration;
    SnapshotIdentifier?: string;
    SourceDBClusterIdentifier?: string;
    SourceRegion?: string;
    StorageEncrypted?: boolean;
    Tags?: Array<Tag>;
    UseLatestRestorableTime?: boolean;
    VpcSecurityGroupIds?: Array<string>;
  };
}

export interface Alexa_ASK_Skill {
  Type: "Alexa::ASK::Skill";
  Properties: {
    AuthenticationConfiguration: AuthenticationConfiguration;
    VendorId: string;
    SkillPackage: SkillPackage;
  };
}

export interface AWS_EC2_ClientVpnEndpoint {
  Type: "AWS::EC2::ClientVpnEndpoint";
  Properties: {
    ClientCidrBlock: string;
    ClientConnectOptions?: ClientConnectOptions;
    Description?: string;
    TagSpecifications?: Array<AWS_EC2_ClientVpnEndpoint____TagSpecification>;
    AuthenticationOptions: Array<ClientAuthenticationRequest>;
    ServerCertificateArn: string;
    DnsServers?: Array<string>;
    SecurityGroupIds?: Array<string>;
    ConnectionLogOptions: ConnectionLogOptions;
    SplitTunnel?: boolean;
    VpcId?: string;
    SelfServicePortal?: string;
    TransportProtocol?: string;
    VpnPort?: number;
  };
}

export interface AWS_ECS_Service {
  Type: "AWS::ECS::Service";
  Properties: {
    CapacityProviderStrategy?: Array<AWS_ECS_Service____CapacityProviderStrategyItem>;
    Cluster?: string;
    DeploymentConfiguration?: DeploymentConfiguration;
    DeploymentController?: DeploymentController;
    DesiredCount?: number;
    EnableECSManagedTags?: boolean;
    EnableExecuteCommand?: boolean;
    HealthCheckGracePeriodSeconds?: number;
    LaunchType?: string;
    LoadBalancers?: Array<AWS_ECS_Service____LoadBalancer>;
    NetworkConfiguration?: AWS_ECS_Service____NetworkConfiguration;
    PlacementConstraints?: Array<PlacementConstraint>;
    PlacementStrategies?: Array<PlacementStrategy>;
    PlatformVersion?: string;
    PropagateTags?: string;
    Role?: string;
    SchedulingStrategy?: string;
    ServiceName?: string;
    ServiceRegistries?: Array<AWS_ECS_Service____ServiceRegistry>;
    Tags?: Array<Tag>;
    TaskDefinition?: string;
  };
}

export interface AWS_IAM_UserToGroupAddition {
  Type: "AWS::IAM::UserToGroupAddition";
  Properties: {
    GroupName: string;
    Users: Array<string>;
  };
}

export interface AWS_GroundStation_MissionProfile {
  Type: "AWS::GroundStation::MissionProfile";
  Properties: {
    Name: string;
    ContactPrePassDurationSeconds?: number;
    ContactPostPassDurationSeconds?: number;
    MinimumViableContactDurationSeconds: number;
    DataflowEdges: Array<DataflowEdge>;
    TrackingConfigArn: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_OpsWorksCM_Server {
  Type: "AWS::OpsWorksCM::Server";
  Properties: {
    KeyPair?: string;
    EngineVersion?: string;
    ServiceRoleArn: string;
    DisableAutomatedBackup?: boolean;
    BackupId?: string;
    EngineModel?: string;
    PreferredMaintenanceWindow?: string;
    AssociatePublicIpAddress?: boolean;
    InstanceProfileArn: string;
    CustomCertificate?: string;
    PreferredBackupWindow?: string;
    SecurityGroupIds?: Array<string>;
    SubnetIds?: Array<string>;
    CustomDomain?: string;
    CustomPrivateKey?: string;
    ServerName?: string;
    EngineAttributes?: Array<EngineAttribute>;
    BackupRetentionCount?: number;
    InstanceType: string;
    Tags?: Array<Tag>;
    Engine?: string;
  };
}

export interface AWS_IoT_Thing {
  Type: "AWS::IoT::Thing";
  Properties: {
    AttributePayload?: AttributePayload;
    ThingName?: string;
  };
}

export interface AWS_Batch_JobQueue {
  Type: "AWS::Batch::JobQueue";
  Properties: {
    ComputeEnvironmentOrder: Array<ComputeEnvironmentOrder>;
    Priority: number;
    State?: string;
    JobQueueName?: string;
    Tags?: any;
  };
}

export interface AWS_OpsWorks_Layer {
  Type: "AWS::OpsWorks::Layer";
  Properties: {
    Attributes?: Record<string, string>;
    AutoAssignElasticIps: boolean;
    AutoAssignPublicIps: boolean;
    CustomInstanceProfileArn?: string;
    CustomJson?: any;
    CustomRecipes?: Recipes;
    CustomSecurityGroupIds?: Array<string>;
    EnableAutoHealing: boolean;
    InstallUpdatesOnBoot?: boolean;
    LifecycleEventConfiguration?: LifecycleEventConfiguration;
    LoadBasedAutoScaling?: LoadBasedAutoScaling;
    Name: string;
    Packages?: Array<string>;
    Shortname: string;
    StackId: string;
    Tags?: Array<Tag>;
    Type: string;
    UseEbsOptimizedInstances?: boolean;
    VolumeConfigurations?: Array<VolumeConfiguration>;
  };
}

export interface AWS_DMS_Certificate {
  Type: "AWS::DMS::Certificate";
  Properties: {
    CertificateIdentifier?: string;
    CertificatePem?: string;
    CertificateWallet?: string;
  };
}

export interface AWS_ApiGateway_ApiKey {
  Type: "AWS::ApiGateway::ApiKey";
  Properties: {
    CustomerId?: string;
    Description?: string;
    Enabled?: boolean;
    GenerateDistinctId?: boolean;
    Name?: string;
    StageKeys?: Array<StageKey>;
    Tags?: Array<Tag>;
    Value?: string;
  };
}

export interface AWS_Timestream_Table {
  Type: "AWS::Timestream::Table";
  Properties: {
    DatabaseName: string;
    TableName?: string;
    RetentionProperties?: any;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Glue_Table {
  Type: "AWS::Glue::Table";
  Properties: {
    TableInput: TableInput;
    DatabaseName: string;
    CatalogId: string;
  };
}

export interface AWS_EC2_SubnetRouteTableAssociation {
  Type: "AWS::EC2::SubnetRouteTableAssociation";
  Properties: {
    RouteTableId: string;
    SubnetId: string;
  };
}

export interface AWS_ElastiCache_SecurityGroup {
  Type: "AWS::ElastiCache::SecurityGroup";
  Properties: {
    Description: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_IAM_InstanceProfile {
  Type: "AWS::IAM::InstanceProfile";
  Properties: {
    InstanceProfileName?: string;
    Path?: string;
    Roles: Array<string>;
  };
}

export interface AWS_IoT_Policy {
  Type: "AWS::IoT::Policy";
  Properties: {
    PolicyDocument: any;
    PolicyName?: string;
  };
}

export interface AWS_CodeDeploy_DeploymentGroup {
  Type: "AWS::CodeDeploy::DeploymentGroup";
  Properties: {
    AlarmConfiguration?: AlarmConfiguration;
    ApplicationName: string;
    AutoRollbackConfiguration?: AutoRollbackConfiguration;
    AutoScalingGroups?: Array<string>;
    Deployment?: Deployment;
    DeploymentConfigName?: string;
    DeploymentGroupName?: string;
    DeploymentStyle?: DeploymentStyle;
    Ec2TagFilters?: Array<EC2TagFilter>;
    Ec2TagSet?: EC2TagSet;
    LoadBalancerInfo?: LoadBalancerInfo;
    OnPremisesInstanceTagFilters?: Array<AWS_CodeDeploy_DeploymentGroup____TagFilter>;
    OnPremisesTagSet?: OnPremisesTagSet;
    ServiceRoleArn: string;
    TriggerConfigurations?: Array<AWS_CodeDeploy_DeploymentGroup____TriggerConfig>;
  };
}

export interface AWS_MediaConnect_Flow {
  Type: "AWS::MediaConnect::Flow";
  Properties: {
    Name: string;
    AvailabilityZone?: string;
    Source: AWS_MediaConnect_Flow____Source;
    SourceFailoverConfig?: FailoverConfig;
  };
}

export interface AWS_Batch_ComputeEnvironment {
  Type: "AWS::Batch::ComputeEnvironment";
  Properties: {
    Type: string;
    ServiceRole?: string;
    ComputeEnvironmentName?: string;
    ComputeResources?: ComputeResources;
    State?: string;
    Tags?: any;
  };
}

export interface AWS_AppFlow_Flow {
  Type: "AWS::AppFlow::Flow";
  Properties: {
    FlowName: string;
    Description?: string;
    KMSArn?: string;
    TriggerConfig: AWS_AppFlow_Flow____TriggerConfig;
    SourceFlowConfig: SourceFlowConfig;
    DestinationFlowConfigList: Array<DestinationFlowConfig>;
    Tasks: Array<Task>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_Route {
  Type: "AWS::EC2::Route";
  Properties: {
    CarrierGatewayId?: string;
    DestinationCidrBlock?: string;
    DestinationIpv6CidrBlock?: string;
    EgressOnlyInternetGatewayId?: string;
    GatewayId?: string;
    InstanceId?: string;
    LocalGatewayId?: string;
    NatGatewayId?: string;
    NetworkInterfaceId?: string;
    RouteTableId: string;
    TransitGatewayId?: string;
    VpcEndpointId?: string;
    VpcPeeringConnectionId?: string;
  };
}

export interface AWS_EC2_LocalGatewayRouteTableVPCAssociation {
  Type: "AWS::EC2::LocalGatewayRouteTableVPCAssociation";
  Properties: {
    LocalGatewayRouteTableId: string;
    VpcId: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_GameLift_GameSessionQueue {
  Type: "AWS::GameLift::GameSessionQueue";
  Properties: {
    TimeoutInSeconds?: number;
    PlayerLatencyPolicies?: Array<PlayerLatencyPolicy>;
    Destinations?: Array<AWS_GameLift_GameSessionQueue____Destination>;
    NotificationTarget?: string;
    FilterConfiguration?: FilterConfiguration;
    CustomEventData?: string;
    Name: string;
    PriorityConfiguration?: PriorityConfiguration;
  };
}

export interface AWS_ApiGateway_Resource {
  Type: "AWS::ApiGateway::Resource";
  Properties: {
    ParentId: string;
    PathPart: string;
    RestApiId: string;
  };
}

export interface AWS_SageMaker_DeviceFleet {
  Type: "AWS::SageMaker::DeviceFleet";
  Properties: {
    Description?: string;
    DeviceFleetName: string;
    OutputConfig: EdgeOutputConfig;
    RoleArn: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_GlobalAccelerator_EndpointGroup {
  Type: "AWS::GlobalAccelerator::EndpointGroup";
  Properties: {
    ListenerArn: string;
    EndpointGroupRegion: string;
    EndpointConfigurations?: Array<AWS_GlobalAccelerator_EndpointGroup____EndpointConfiguration>;
    TrafficDialPercentage?: number;
    HealthCheckPort?: number;
    HealthCheckProtocol?: string;
    HealthCheckPath?: string;
    HealthCheckIntervalSeconds?: number;
    ThresholdCount?: number;
    PortOverrides?: Array<PortOverride>;
  };
}

export interface AWS_SecurityHub_Hub {
  Type: "AWS::SecurityHub::Hub";
  Properties: {
    Tags?: any;
  };
}

export interface AWS_IoT1Click_Device {
  Type: "AWS::IoT1Click::Device";
  Properties: {
    DeviceId: string;
    Enabled: boolean;
  };
}

export interface AWS_Glue_Connection {
  Type: "AWS::Glue::Connection";
  Properties: {
    ConnectionInput: ConnectionInput;
    CatalogId: string;
  };
}

export interface AWS_Macie_CustomDataIdentifier {
  Type: "AWS::Macie::CustomDataIdentifier";
  Properties: {
    Name: string;
    Description?: string;
    Regex: string;
    MaximumMatchDistance?: number;
    Keywords?: Array<string>;
    IgnoreWords?: Array<string>;
  };
}

export interface AWS_ECS_TaskSet {
  Type: "AWS::ECS::TaskSet";
  Properties: {
    Cluster: string;
    ExternalId?: string;
    LaunchType?: string;
    LoadBalancers?: Array<AWS_ECS_TaskSet____LoadBalancer>;
    NetworkConfiguration?: AWS_ECS_TaskSet____NetworkConfiguration;
    PlatformVersion?: string;
    Scale?: Scale;
    Service: string;
    ServiceRegistries?: Array<AWS_ECS_TaskSet____ServiceRegistry>;
    TaskDefinition: string;
  };
}

export interface AWS_WAFv2_RuleGroup {
  Type: "AWS::WAFv2::RuleGroup";
  Properties: {
    Capacity: number;
    Description?: string;
    Name?: string;
    Scope: string;
    Rules?: Array<AWS_WAFv2_RuleGroup____Rule>;
    VisibilityConfig: AWS_WAFv2_RuleGroup____VisibilityConfig;
    Tags?: Array<Tag>;
    CustomResponseBodies?: Record<
      string,
      AWS_WAFv2_RuleGroup____CustomResponseBody
    >;
  };
}

export interface AWS_ElasticBeanstalk_Application {
  Type: "AWS::ElasticBeanstalk::Application";
  Properties: {
    ApplicationName?: string;
    Description?: string;
    ResourceLifecycleConfig?: ApplicationResourceLifecycleConfig;
  };
}

export interface AWS_ServiceCatalogAppRegistry_AttributeGroupAssociation {
  Type: "AWS::ServiceCatalogAppRegistry::AttributeGroupAssociation";
  Properties: {
    Application: string;
    AttributeGroup: string;
  };
}

export interface AWS_S3Outposts_Endpoint {
  Type: "AWS::S3Outposts::Endpoint";
  Properties: {
    OutpostId: string;
    SecurityGroupId: string;
    SubnetId: string;
  };
}

export interface AWS_FraudDetector_Label {
  Type: "AWS::FraudDetector::Label";
  Properties: {
    Name: string;
    Tags?: Array<Tag>;
    Description?: string;
  };
}

export interface AWS_AppFlow_ConnectorProfile {
  Type: "AWS::AppFlow::ConnectorProfile";
  Properties: {
    ConnectorProfileName: string;
    KMSArn?: string;
    ConnectorType: string;
    ConnectionMode: string;
    ConnectorProfileConfig?: ConnectorProfileConfig;
  };
}

export interface AWS_WAFv2_WebACL {
  Type: "AWS::WAFv2::WebACL";
  Properties: {
    DefaultAction: DefaultAction;
    Description?: string;
    Name?: string;
    Scope: string;
    Rules?: Array<AWS_WAFv2_WebACL____Rule>;
    VisibilityConfig: AWS_WAFv2_WebACL____VisibilityConfig;
    Tags?: Array<Tag>;
    CustomResponseBodies?: Record<
      string,
      AWS_WAFv2_WebACL____CustomResponseBody
    >;
  };
}

export interface AWS_ElastiCache_SubnetGroup {
  Type: "AWS::ElastiCache::SubnetGroup";
  Properties: {
    CacheSubnetGroupName?: string;
    Description: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_TransitGatewayRouteTablePropagation {
  Type: "AWS::EC2::TransitGatewayRouteTablePropagation";
  Properties: {
    TransitGatewayRouteTableId: string;
    TransitGatewayAttachmentId: string;
  };
}

export interface AWS_SageMaker_App {
  Type: "AWS::SageMaker::App";
  Properties: {
    AppName: string;
    AppType: string;
    DomainId: string;
    ResourceSpec?: AWS_SageMaker_App____ResourceSpec;
    Tags?: Array<Tag>;
    UserProfileName: string;
  };
}

export interface AWS_WAFRegional_ByteMatchSet {
  Type: "AWS::WAFRegional::ByteMatchSet";
  Properties: {
    ByteMatchTuples?: Array<AWS_WAFRegional_ByteMatchSet____ByteMatchTuple>;
    Name: string;
  };
}

export interface AWS_Detective_Graph {
  Type: "AWS::Detective::Graph";
  Properties: {
    Tags?: Array<Tag>;
  };
}

export interface AWS_SageMaker_Domain {
  Type: "AWS::SageMaker::Domain";
  Properties: {
    AppNetworkAccessType?: string;
    AuthMode: string;
    DefaultUserSettings: AWS_SageMaker_Domain____UserSettings;
    DomainName: string;
    KmsKeyId?: string;
    SubnetIds: Array<string>;
    Tags?: Array<Tag>;
    VpcId: string;
  };
}

export interface AWS_EC2_NetworkInterface {
  Type: "AWS::EC2::NetworkInterface";
  Properties: {
    Description?: string;
    GroupSet?: Array<string>;
    InterfaceType?: string;
    Ipv6AddressCount?: number;
    Ipv6Addresses?: Array<AWS_EC2_NetworkInterface____InstanceIpv6Address>;
    PrivateIpAddress?: string;
    PrivateIpAddresses?: Array<AWS_EC2_NetworkInterface____PrivateIpAddressSpecification>;
    SecondaryPrivateIpAddressCount?: number;
    SourceDestCheck?: boolean;
    SubnetId: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ApiGatewayV2_Deployment {
  Type: "AWS::ApiGatewayV2::Deployment";
  Properties: {
    Description?: string;
    StageName?: string;
    ApiId: string;
  };
}

export interface AWS_AppConfig_Environment {
  Type: "AWS::AppConfig::Environment";
  Properties: {
    Description?: string;
    Monitors?: Array<Monitors>;
    ApplicationId: string;
    Tags?: Array<AWS_AppConfig_Environment____Tags>;
    Name: string;
  };
}

export interface AWS_FSx_FileSystem {
  Type: "AWS::FSx::FileSystem";
  Properties: {
    StorageType?: string;
    KmsKeyId?: string;
    StorageCapacity?: number;
    FileSystemType: string;
    LustreConfiguration?: LustreConfiguration;
    BackupId?: string;
    SubnetIds: Array<string>;
    SecurityGroupIds?: Array<string>;
    Tags?: Array<Tag>;
    WindowsConfiguration?: WindowsConfiguration;
  };
}

export interface AWS_OpsWorks_Stack {
  Type: "AWS::OpsWorks::Stack";
  Properties: {
    AgentVersion?: string;
    Attributes?: Record<string, string>;
    ChefConfiguration?: ChefConfiguration;
    CloneAppIds?: Array<string>;
    ClonePermissions?: boolean;
    ConfigurationManager?: StackConfigurationManager;
    CustomCookbooksSource?: AWS_OpsWorks_Stack____Source;
    CustomJson?: any;
    DefaultAvailabilityZone?: string;
    DefaultInstanceProfileArn: string;
    DefaultOs?: string;
    DefaultRootDeviceType?: string;
    DefaultSshKeyName?: string;
    DefaultSubnetId?: string;
    EcsClusterArn?: string;
    ElasticIps?: Array<ElasticIp>;
    HostnameTheme?: string;
    Name: string;
    RdsDbInstances?: Array<RdsDbInstance>;
    ServiceRoleArn: string;
    SourceStackId?: string;
    Tags?: Array<Tag>;
    UseCustomCookbooks?: boolean;
    UseOpsworksSecurityGroups?: boolean;
    VpcId?: string;
  };
}

export interface AWS_DataPipeline_Pipeline {
  Type: "AWS::DataPipeline::Pipeline";
  Properties: {
    Activate?: boolean;
    Description?: string;
    Name: string;
    ParameterObjects: Array<ParameterObject>;
    ParameterValues?: Array<ParameterValue>;
    PipelineObjects?: Array<PipelineObject>;
    PipelineTags?: Array<PipelineTag>;
  };
}

export interface AWS_EC2_TransitGatewayMulticastGroupSource {
  Type: "AWS::EC2::TransitGatewayMulticastGroupSource";
  Properties: {
    GroupIpAddress: string;
    TransitGatewayMulticastDomainId: string;
    NetworkInterfaceId: string;
  };
}

export interface AWS_Route53Resolver_ResolverRule {
  Type: "AWS::Route53Resolver::ResolverRule";
  Properties: {
    ResolverEndpointId?: string;
    DomainName: string;
    RuleType: string;
    TargetIps?: Array<TargetAddress>;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_NetworkManager_LinkAssociation {
  Type: "AWS::NetworkManager::LinkAssociation";
  Properties: {
    GlobalNetworkId: string;
    DeviceId: string;
    LinkId: string;
  };
}

export interface AWS_EC2_ClientVpnAuthorizationRule {
  Type: "AWS::EC2::ClientVpnAuthorizationRule";
  Properties: {
    ClientVpnEndpointId: string;
    Description?: string;
    AccessGroupId?: string;
    TargetNetworkCidr: string;
    AuthorizeAllGroups?: boolean;
  };
}

export interface AWS_EC2_SubnetNetworkAclAssociation {
  Type: "AWS::EC2::SubnetNetworkAclAssociation";
  Properties: {
    NetworkAclId: string;
    SubnetId: string;
  };
}

export interface AWS_SageMaker_Project {
  Type: "AWS::SageMaker::Project";
  Properties: {
    Tags?: Array<Tag>;
    ProjectName: string;
    ProjectDescription?: string;
    ServiceCatalogProvisioningDetails: any;
  };
}

export interface AWS_GameLift_Script {
  Type: "AWS::GameLift::Script";
  Properties: {
    Version?: string;
    StorageLocation: AWS_GameLift_Script____S3Location;
    Name?: string;
  };
}

export interface AWS_ApiGateway_Account {
  Type: "AWS::ApiGateway::Account";
  Properties: {
    CloudWatchRoleArn?: string;
  };
}

export interface AWS_EC2_TrafficMirrorSession {
  Type: "AWS::EC2::TrafficMirrorSession";
  Properties: {
    TrafficMirrorTargetId: string;
    Description?: string;
    SessionNumber: number;
    VirtualNetworkId?: number;
    PacketLength?: number;
    NetworkInterfaceId: string;
    TrafficMirrorFilterId: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Amplify_Branch {
  Type: "AWS::Amplify::Branch";
  Properties: {
    Description?: string;
    EnvironmentVariables?: Array<AWS_Amplify_Branch____EnvironmentVariable>;
    AppId: string;
    PullRequestEnvironmentName?: string;
    EnablePullRequestPreview?: boolean;
    EnableAutoBuild?: boolean;
    EnablePerformanceMode?: boolean;
    BuildSpec?: string;
    Stage?: string;
    BranchName: string;
    BasicAuthConfig?: AWS_Amplify_Branch____BasicAuthConfig;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Greengrass_LoggerDefinition {
  Type: "AWS::Greengrass::LoggerDefinition";
  Properties: {
    InitialVersion?: LoggerDefinitionVersion;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_ServiceCatalog_CloudFormationProvisionedProduct {
  Type: "AWS::ServiceCatalog::CloudFormationProvisionedProduct";
  Properties: {
    AcceptLanguage?: string;
    NotificationArns?: Array<string>;
    PathId?: string;
    PathName?: string;
    ProductId?: string;
    ProductName?: string;
    ProvisionedProductName?: string;
    ProvisioningArtifactId?: string;
    ProvisioningArtifactName?: string;
    ProvisioningParameters?: Array<ProvisioningParameter>;
    ProvisioningPreferences?: ProvisioningPreferences;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ServiceCatalog_LaunchRoleConstraint {
  Type: "AWS::ServiceCatalog::LaunchRoleConstraint";
  Properties: {
    Description?: string;
    LocalRoleName?: string;
    AcceptLanguage?: string;
    PortfolioId: string;
    ProductId: string;
    RoleArn?: string;
  };
}

export interface AWS_EC2_SubnetCidrBlock {
  Type: "AWS::EC2::SubnetCidrBlock";
  Properties: {
    Ipv6CidrBlock: string;
    SubnetId: string;
  };
}

export interface AWS_AutoScaling_LifecycleHook {
  Type: "AWS::AutoScaling::LifecycleHook";
  Properties: {
    AutoScalingGroupName: string;
    DefaultResult?: string;
    HeartbeatTimeout?: number;
    LifecycleHookName?: string;
    LifecycleTransition: string;
    NotificationMetadata?: string;
    NotificationTargetARN?: string;
    RoleARN?: string;
  };
}

export interface AWS_Redshift_ClusterSecurityGroupIngress {
  Type: "AWS::Redshift::ClusterSecurityGroupIngress";
  Properties: {
    CIDRIP?: string;
    ClusterSecurityGroupName: string;
    EC2SecurityGroupName?: string;
    EC2SecurityGroupOwnerId?: string;
  };
}

export interface AWS_ElastiCache_SecurityGroupIngress {
  Type: "AWS::ElastiCache::SecurityGroupIngress";
  Properties: {
    CacheSecurityGroupName: string;
    EC2SecurityGroupName: string;
    EC2SecurityGroupOwnerId?: string;
  };
}

export interface AWS_EC2_NatGateway {
  Type: "AWS::EC2::NatGateway";
  Properties: {
    AllocationId: string;
    SubnetId: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_RDS_OptionGroup {
  Type: "AWS::RDS::OptionGroup";
  Properties: {
    EngineName: string;
    MajorEngineVersion: string;
    OptionConfigurations: Array<OptionConfiguration>;
    OptionGroupDescription: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CodeArtifact_Domain {
  Type: "AWS::CodeArtifact::Domain";
  Properties: {
    DomainName: string;
    EncryptionKey?: string;
    PermissionsPolicyDocument?: any;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ElastiCache_ReplicationGroup {
  Type: "AWS::ElastiCache::ReplicationGroup";
  Properties: {
    AtRestEncryptionEnabled?: boolean;
    AuthToken?: string;
    AutoMinorVersionUpgrade?: boolean;
    AutomaticFailoverEnabled?: boolean;
    CacheNodeType?: string;
    CacheParameterGroupName?: string;
    CacheSecurityGroupNames?: Array<string>;
    CacheSubnetGroupName?: string;
    Engine?: string;
    EngineVersion?: string;
    GlobalReplicationGroupId?: string;
    KmsKeyId?: string;
    LogDeliveryConfigurations?: Array<AWS_ElastiCache_ReplicationGroup____LogDeliveryConfigurationRequest>;
    MultiAZEnabled?: boolean;
    NodeGroupConfiguration?: Array<NodeGroupConfiguration>;
    NotificationTopicArn?: string;
    NumCacheClusters?: number;
    NumNodeGroups?: number;
    Port?: number;
    PreferredCacheClusterAZs?: Array<string>;
    PreferredMaintenanceWindow?: string;
    PrimaryClusterId?: string;
    ReplicasPerNodeGroup?: number;
    ReplicationGroupDescription: string;
    ReplicationGroupId?: string;
    SecurityGroupIds?: Array<string>;
    SnapshotArns?: Array<string>;
    SnapshotName?: string;
    SnapshotRetentionLimit?: number;
    SnapshotWindow?: string;
    SnapshottingClusterId?: string;
    Tags?: Array<Tag>;
    TransitEncryptionEnabled?: boolean;
    UserGroupIds?: Array<string>;
  };
}

export interface AWS_Cognito_UserPoolUser {
  Type: "AWS::Cognito::UserPoolUser";
  Properties: {
    ValidationData?: Array<AttributeType>;
    UserPoolId: string;
    Username?: string;
    MessageAction?: string;
    ClientMetadata?: any;
    DesiredDeliveryMediums?: Array<string>;
    ForceAliasCreation?: boolean;
    UserAttributes?: Array<AttributeType>;
  };
}

export interface AWS_AppSync_FunctionConfiguration {
  Type: "AWS::AppSync::FunctionConfiguration";
  Properties: {
    ResponseMappingTemplateS3Location?: string;
    Description?: string;
    DataSourceName: string;
    RequestMappingTemplate?: string;
    ResponseMappingTemplate?: string;
    FunctionVersion: string;
    SyncConfig?: AWS_AppSync_FunctionConfiguration____SyncConfig;
    RequestMappingTemplateS3Location?: string;
    ApiId: string;
    Name: string;
  };
}

export interface AWS_ApiGatewayV2_Model {
  Type: "AWS::ApiGatewayV2::Model";
  Properties: {
    Description?: string;
    ContentType?: string;
    Schema: any;
    ApiId: string;
    Name: string;
  };
}

export interface AWS_Signer_SigningProfile {
  Type: "AWS::Signer::SigningProfile";
  Properties: {
    SignatureValidityPeriod?: SignatureValidityPeriod;
    PlatformId: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CloudFormation_WaitCondition {
  Type: "AWS::CloudFormation::WaitCondition";
  Properties: {
    Count?: number;
    Handle?: string;
    Timeout?: string;
  };
}

export interface AWS_EC2_SecurityGroup {
  Type: "AWS::EC2::SecurityGroup";
  Properties: {
    GroupDescription: string;
    GroupName?: string;
    SecurityGroupEgress?: Array<Egress>;
    SecurityGroupIngress?: Array<AWS_EC2_SecurityGroup____Ingress>;
    Tags?: Array<Tag>;
    VpcId?: string;
  };
}

export interface AWS_EKS_FargateProfile {
  Type: "AWS::EKS::FargateProfile";
  Properties: {
    ClusterName: string;
    FargateProfileName?: string;
    PodExecutionRoleArn: string;
    Subnets?: Array<string>;
    Selectors: Array<Selector>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_LookoutMetrics_AnomalyDetector {
  Type: "AWS::LookoutMetrics::AnomalyDetector";
  Properties: {
    AnomalyDetectorName?: string;
    AnomalyDetectorDescription?: string;
    AnomalyDetectorConfig: any;
    MetricSetList: Array<MetricSet>;
    KmsKeyArn?: string;
  };
}

export interface AWS_CloudFront_OriginRequestPolicy {
  Type: "AWS::CloudFront::OriginRequestPolicy";
  Properties: {
    OriginRequestPolicyConfig: OriginRequestPolicyConfig;
  };
}

export interface AWS_CloudFormation_ResourceVersion {
  Type: "AWS::CloudFormation::ResourceVersion";
  Properties: {
    ExecutionRoleArn?: string;
    LoggingConfig?: LoggingConfig;
    SchemaHandlerPackage: string;
    TypeName: string;
  };
}

export interface AWS_WAFRegional_Rule {
  Type: "AWS::WAFRegional::Rule";
  Properties: {
    MetricName: string;
    Predicates?: Array<AWS_WAFRegional_Rule____Predicate>;
    Name: string;
  };
}

export interface AWS_SSO_PermissionSet {
  Type: "AWS::SSO::PermissionSet";
  Properties: {
    Name: string;
    Description?: string;
    InstanceArn: string;
    SessionDuration?: string;
    RelayStateType?: string;
    ManagedPolicies?: Array<string>;
    InlinePolicy?: any;
    Tags?: Array<Tag>;
  };
}

export interface AWS_AppConfig_DeploymentStrategy {
  Type: "AWS::AppConfig::DeploymentStrategy";
  Properties: {
    ReplicateTo: string;
    GrowthType?: string;
    Description?: string;
    DeploymentDurationInMinutes: number;
    GrowthFactor: number;
    FinalBakeTimeInMinutes?: number;
    Tags?: Array<AWS_AppConfig_DeploymentStrategy____Tags>;
    Name: string;
  };
}

export interface AWS_EC2_TrafficMirrorFilterRule {
  Type: "AWS::EC2::TrafficMirrorFilterRule";
  Properties: {
    DestinationPortRange?: TrafficMirrorPortRange;
    Description?: string;
    SourcePortRange?: TrafficMirrorPortRange;
    RuleAction: string;
    SourceCidrBlock: string;
    RuleNumber: number;
    DestinationCidrBlock: string;
    TrafficMirrorFilterId: string;
    TrafficDirection: string;
    Protocol?: number;
  };
}

export interface AWS_ApiGateway_RestApi {
  Type: "AWS::ApiGateway::RestApi";
  Properties: {
    ApiKeySourceType?: string;
    BinaryMediaTypes?: Array<string>;
    Body?: any;
    BodyS3Location?: AWS_ApiGateway_RestApi____S3Location;
    CloneFrom?: string;
    Description?: string;
    DisableExecuteApiEndpoint?: boolean;
    EndpointConfiguration?: AWS_ApiGateway_RestApi____EndpointConfiguration;
    FailOnWarnings?: boolean;
    MinimumCompressionSize?: number;
    Name?: string;
    Parameters?: Record<string, string>;
    Policy?: any;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CloudFront_PublicKey {
  Type: "AWS::CloudFront::PublicKey";
  Properties: {
    PublicKeyConfig: PublicKeyConfig;
  };
}

export interface AWS_Events_EventBus {
  Type: "AWS::Events::EventBus";
  Properties: {
    EventSourceName?: string;
    Name: string;
  };
}

export interface AWS_DataBrew_Schedule {
  Type: "AWS::DataBrew::Schedule";
  Properties: {
    JobNames?: Array<string>;
    CronExpression: string;
    Name: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Lambda_EventInvokeConfig {
  Type: "AWS::Lambda::EventInvokeConfig";
  Properties: {
    FunctionName: string;
    MaximumRetryAttempts?: number;
    DestinationConfig?: AWS_Lambda_EventInvokeConfig____DestinationConfig;
    Qualifier: string;
    MaximumEventAgeInSeconds?: number;
  };
}

export interface AWS_EC2_PrefixList {
  Type: "AWS::EC2::PrefixList";
  Properties: {
    PrefixListName: string;
    AddressFamily: string;
    MaxEntries: number;
    Tags?: Array<Tag>;
    Entries?: Array<Entry>;
  };
}

export interface AWS_EC2_VPC {
  Type: "AWS::EC2::VPC";
  Properties: {
    CidrBlock: string;
    EnableDnsHostnames?: boolean;
    EnableDnsSupport?: boolean;
    InstanceTenancy?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_CodeGuruProfiler_ProfilingGroup {
  Type: "AWS::CodeGuruProfiler::ProfilingGroup";
  Properties: {
    ProfilingGroupName: string;
    ComputePlatform?: string;
    AgentPermissions?: any;
    AnomalyDetectionNotificationConfiguration?: Array<AWS_CodeGuruProfiler_ProfilingGroup____Channel>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Athena_DataCatalog {
  Type: "AWS::Athena::DataCatalog";
  Properties: {
    Name: string;
    Description?: string;
    Parameters?: Record<string, string>;
    Tags?: Array<Tag>;
    Type: string;
  };
}

export interface AWS_NetworkFirewall_LoggingConfiguration {
  Type: "AWS::NetworkFirewall::LoggingConfiguration";
  Properties: {
    FirewallName?: string;
    FirewallArn: string;
    LoggingConfiguration: AWS_NetworkFirewall_LoggingConfiguration____LoggingConfiguration;
  };
}

export interface AWS_Config_OrganizationConformancePack {
  Type: "AWS::Config::OrganizationConformancePack";
  Properties: {
    OrganizationConformancePackName: string;
    TemplateS3Uri?: string;
    TemplateBody?: string;
    DeliveryS3Bucket?: string;
    DeliveryS3KeyPrefix?: string;
    ConformancePackInputParameters?: Array<AWS_Config_OrganizationConformancePack____ConformancePackInputParameter>;
    ExcludedAccounts?: Array<string>;
  };
}

export interface AWS_KinesisAnalyticsV2_ApplicationOutput {
  Type: "AWS::KinesisAnalyticsV2::ApplicationOutput";
  Properties: {
    ApplicationName: string;
    Output: AWS_KinesisAnalyticsV2_ApplicationOutput____Output;
  };
}

export interface AWS_ElastiCache_ParameterGroup {
  Type: "AWS::ElastiCache::ParameterGroup";
  Properties: {
    CacheParameterGroupFamily: string;
    Description: string;
    Properties?: Record<string, string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_NetworkManager_GlobalNetwork {
  Type: "AWS::NetworkManager::GlobalNetwork";
  Properties: {
    Description?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_NetworkManager_TransitGatewayRegistration {
  Type: "AWS::NetworkManager::TransitGatewayRegistration";
  Properties: {
    GlobalNetworkId: string;
    TransitGatewayArn: string;
  };
}

export interface AWS_SQS_QueuePolicy {
  Type: "AWS::SQS::QueuePolicy";
  Properties: {
    PolicyDocument: any;
    Queues: Array<string>;
  };
}

export interface AWS_ApplicationAutoScaling_ScalingPolicy {
  Type: "AWS::ApplicationAutoScaling::ScalingPolicy";
  Properties: {
    PolicyName: string;
    PolicyType: string;
    ResourceId?: string;
    ScalableDimension?: string;
    ScalingTargetId?: string;
    ServiceNamespace?: string;
    StepScalingPolicyConfiguration?: StepScalingPolicyConfiguration;
    TargetTrackingScalingPolicyConfiguration?: TargetTrackingScalingPolicyConfiguration;
  };
}

export interface AWS_WAF_SqlInjectionMatchSet {
  Type: "AWS::WAF::SqlInjectionMatchSet";
  Properties: {
    Name: string;
    SqlInjectionMatchTuples?: Array<AWS_WAF_SqlInjectionMatchSet____SqlInjectionMatchTuple>;
  };
}

export interface AWS_EFS_FileSystem {
  Type: "AWS::EFS::FileSystem";
  Properties: {
    Encrypted?: boolean;
    FileSystemTags?: Array<ElasticFileSystemTag>;
    KmsKeyId?: string;
    LifecyclePolicies?: Array<AWS_EFS_FileSystem____LifecyclePolicy>;
    PerformanceMode?: string;
    ProvisionedThroughputInMibps?: number;
    ThroughputMode?: string;
    FileSystemPolicy?: any;
    BypassPolicyLockoutSafetyCheck?: boolean;
    BackupPolicy?: BackupPolicy;
    AvailabilityZoneName?: string;
  };
}

export interface AWS_CodeCommit_Repository {
  Type: "AWS::CodeCommit::Repository";
  Properties: {
    RepositoryName: string;
    Triggers?: Array<RepositoryTrigger>;
    Code?: AWS_CodeCommit_Repository____Code;
    RepositoryDescription?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SecretsManager_Secret {
  Type: "AWS::SecretsManager::Secret";
  Properties: {
    Description?: string;
    KmsKeyId?: string;
    SecretString?: string;
    GenerateSecretString?: GenerateSecretString;
    ReplicaRegions?: Array<ReplicaRegion>;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_IoT_ScheduledAudit {
  Type: "AWS::IoT::ScheduledAudit";
  Properties: {
    ScheduledAuditName?: string;
    Frequency: string;
    DayOfMonth?: string;
    DayOfWeek?: string;
    TargetCheckNames: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ServiceCatalog_Portfolio {
  Type: "AWS::ServiceCatalog::Portfolio";
  Properties: {
    ProviderName: string;
    Description?: string;
    DisplayName: string;
    AcceptLanguage?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EMR_StudioSessionMapping {
  Type: "AWS::EMR::StudioSessionMapping";
  Properties: {
    IdentityName: string;
    IdentityType: string;
    SessionPolicyArn: string;
    StudioId: string;
  };
}

export interface AWS_Greengrass_CoreDefinition {
  Type: "AWS::Greengrass::CoreDefinition";
  Properties: {
    InitialVersion?: CoreDefinitionVersion;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_Cognito_UserPoolUICustomizationAttachment {
  Type: "AWS::Cognito::UserPoolUICustomizationAttachment";
  Properties: {
    CSS?: string;
    UserPoolId: string;
    ClientId: string;
  };
}

export interface AWS_RDS_DBParameterGroup {
  Type: "AWS::RDS::DBParameterGroup";
  Properties: {
    Description: string;
    Family: string;
    Parameters?: Record<string, string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Logs_LogStream {
  Type: "AWS::Logs::LogStream";
  Properties: {
    LogGroupName: string;
    LogStreamName?: string;
  };
}

export interface AWS_Athena_WorkGroup {
  Type: "AWS::Athena::WorkGroup";
  Properties: {
    Name: string;
    Description?: string;
    Tags?: Array<Tag>;
    WorkGroupConfiguration?: WorkGroupConfiguration;
    WorkGroupConfigurationUpdates?: WorkGroupConfigurationUpdates;
    State?: string;
    RecursiveDeleteOption?: boolean;
  };
}

export interface AWS_Route53Resolver_FirewallRuleGroup {
  Type: "AWS::Route53Resolver::FirewallRuleGroup";
  Properties: {
    Name?: string;
    FirewallRules?: Array<FirewallRule>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_RoboMaker_RobotApplicationVersion {
  Type: "AWS::RoboMaker::RobotApplicationVersion";
  Properties: {
    CurrentRevisionId?: string;
    Application: string;
  };
}

export interface AWS_RDS_EventSubscription {
  Type: "AWS::RDS::EventSubscription";
  Properties: {
    Enabled?: boolean;
    EventCategories?: Array<string>;
    SnsTopicArn: string;
    SourceIds?: Array<string>;
    SourceType?: string;
  };
}

export interface AWS_ElasticBeanstalk_Environment {
  Type: "AWS::ElasticBeanstalk::Environment";
  Properties: {
    ApplicationName: string;
    CNAMEPrefix?: string;
    Description?: string;
    EnvironmentName?: string;
    OperationsRole?: string;
    OptionSettings?: Array<AWS_ElasticBeanstalk_Environment____OptionSetting>;
    PlatformArn?: string;
    SolutionStackName?: string;
    Tags?: Array<Tag>;
    TemplateName?: string;
    Tier?: Tier;
    VersionLabel?: string;
  };
}

export interface AWS_ResourceGroups_Group {
  Type: "AWS::ResourceGroups::Group";
  Properties: {
    Name: string;
    Description?: string;
    ResourceQuery?: ResourceQuery;
    Tags?: Array<Tag>;
    Configuration?: Array<ConfigurationItem>;
    Resources?: Array<string>;
  };
}

export interface AWS_IoTAnalytics_Pipeline {
  Type: "AWS::IoTAnalytics::Pipeline";
  Properties: {
    PipelineName?: string;
    Tags?: Array<Tag>;
    PipelineActivities: Array<Activity>;
  };
}

export interface AWS_Lambda_Function {
  Type: "AWS::Lambda::Function";
  Properties: {
    Code: AWS_Lambda_Function____Code;
    CodeSigningConfigArn?: string;
    DeadLetterConfig?: AWS_Lambda_Function____DeadLetterConfig;
    Description?: string;
    Environment?: AWS_Lambda_Function____Environment;
    FileSystemConfigs?: Array<AWS_Lambda_Function____FileSystemConfig>;
    FunctionName?: string;
    Handler?: string;
    ImageConfig?: AWS_Lambda_Function____ImageConfig;
    KmsKeyArn?: string;
    Layers?: Array<string>;
    MemorySize?: number;
    PackageType?: string;
    ReservedConcurrentExecutions?: number;
    Role: string;
    Runtime?: string;
    Tags?: Array<Tag>;
    Timeout?: number;
    TracingConfig?: TracingConfig;
    VpcConfig?: AWS_Lambda_Function____VpcConfig;
  };
}

export interface AWS_LookoutVision_Project {
  Type: "AWS::LookoutVision::Project";
  Properties: {
    ProjectName: string;
  };
}

export interface AWS_EC2_TransitGatewayRoute {
  Type: "AWS::EC2::TransitGatewayRoute";
  Properties: {
    TransitGatewayRouteTableId: string;
    DestinationCidrBlock?: string;
    Blackhole?: boolean;
    TransitGatewayAttachmentId?: string;
  };
}

export interface AWS_FMS_Policy {
  Type: "AWS::FMS::Policy";
  Properties: {
    ExcludeMap?: IEMap;
    ExcludeResourceTags: boolean;
    IncludeMap?: IEMap;
    PolicyName: string;
    RemediationEnabled: boolean;
    ResourceTags?: Array<ResourceTag>;
    ResourceType: string;
    ResourceTypeList?: Array<string>;
    SecurityServicePolicyData: any;
    DeleteAllPolicyResources?: boolean;
    Tags?: Array<PolicyTag>;
  };
}

export interface AWS_Transfer_User {
  Type: "AWS::Transfer::User";
  Properties: {
    Policy?: string;
    Role: string;
    HomeDirectory?: string;
    HomeDirectoryType?: string;
    ServerId: string;
    UserName: string;
    HomeDirectoryMappings?: Array<HomeDirectoryMapEntry>;
    PosixProfile?: PosixProfile;
    SshPublicKeys?: Array<SshPublicKey>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EventSchemas_Schema {
  Type: "AWS::EventSchemas::Schema";
  Properties: {
    Type: string;
    Description?: string;
    Content: string;
    RegistryName: string;
    SchemaName?: string;
    Tags?: Array<AWS_EventSchemas_Schema____TagsEntry>;
  };
}

export interface AWS_EC2_NetworkAcl {
  Type: "AWS::EC2::NetworkAcl";
  Properties: {
    Tags?: Array<Tag>;
    VpcId: string;
  };
}

export interface AWS_ImageBuilder_DistributionConfiguration {
  Type: "AWS::ImageBuilder::DistributionConfiguration";
  Properties: {
    Name: string;
    Description?: string;
    Distributions: Array<Distribution>;
    Tags?: Record<string, string>;
  };
}

export interface AWS_RDS_DBProxy {
  Type: "AWS::RDS::DBProxy";
  Properties: {
    Auth: Array<AuthFormat>;
    DBProxyName: string;
    DebugLogging?: boolean;
    EngineFamily: string;
    IdleClientTimeout?: number;
    RequireTLS?: boolean;
    RoleArn: string;
    Tags?: Array<AWS_RDS_DBProxy____TagFormat>;
    VpcSecurityGroupIds?: Array<string>;
    VpcSubnetIds: Array<string>;
  };
}

export interface AWS_Config_ConfigRule {
  Type: "AWS::Config::ConfigRule";
  Properties: {
    ConfigRuleName?: string;
    Description?: string;
    InputParameters?: any;
    MaximumExecutionFrequency?: string;
    Scope?: AWS_Config_ConfigRule____Scope;
    Source: AWS_Config_ConfigRule____Source;
  };
}

export interface AWS_QuickSight_DataSet {
  Type: "AWS::QuickSight::DataSet";
  Properties: {
    AwsAccountId?: string;
    ColumnGroups?: Array<ColumnGroup>;
    ColumnLevelPermissionRules?: Array<ColumnLevelPermissionRule>;
    DataSetId?: string;
    FieldFolders?: Record<string, FieldFolder>;
    ImportMode?: string;
    LogicalTableMap?: Record<string, LogicalTable>;
    Name?: string;
    Permissions?: Array<AWS_QuickSight_DataSet____ResourcePermission>;
    PhysicalTableMap?: Record<string, PhysicalTable>;
    RowLevelPermissionDataSet?: RowLevelPermissionDataSet;
    Tags?: Array<Tag>;
    IngestionWaitPolicy?: IngestionWaitPolicy;
  };
}

export interface AWS_Glue_Partition {
  Type: "AWS::Glue::Partition";
  Properties: {
    TableName: string;
    DatabaseName: string;
    CatalogId: string;
    PartitionInput: PartitionInput;
  };
}

export interface AWS_EC2_VPNGatewayRoutePropagation {
  Type: "AWS::EC2::VPNGatewayRoutePropagation";
  Properties: {
    RouteTableIds: Array<string>;
    VpnGatewayId: string;
  };
}

export interface AWS_EC2_ClientVpnTargetNetworkAssociation {
  Type: "AWS::EC2::ClientVpnTargetNetworkAssociation";
  Properties: {
    ClientVpnEndpointId: string;
    SubnetId: string;
  };
}

export interface AWS_WAF_WebACL {
  Type: "AWS::WAF::WebACL";
  Properties: {
    DefaultAction: WafAction;
    MetricName: string;
    Name: string;
    Rules?: Array<ActivatedRule>;
  };
}

export interface AWS_AppSync_ApiCache {
  Type: "AWS::AppSync::ApiCache";
  Properties: {
    Type: string;
    TransitEncryptionEnabled?: boolean;
    AtRestEncryptionEnabled?: boolean;
    ApiId: string;
    ApiCachingBehavior: string;
    Ttl: number;
  };
}

export interface AWS_Neptune_DBCluster {
  Type: "AWS::Neptune::DBCluster";
  Properties: {
    StorageEncrypted?: boolean;
    RestoreToTime?: string;
    EngineVersion?: string;
    KmsKeyId?: string;
    AssociatedRoles?: Array<AWS_Neptune_DBCluster____DBClusterRole>;
    AvailabilityZones?: Array<string>;
    SnapshotIdentifier?: string;
    Port?: number;
    DBClusterIdentifier?: string;
    PreferredMaintenanceWindow?: string;
    IamAuthEnabled?: boolean;
    DBSubnetGroupName?: string;
    DeletionProtection?: boolean;
    PreferredBackupWindow?: string;
    UseLatestRestorableTime?: boolean;
    VpcSecurityGroupIds?: Array<string>;
    SourceDBClusterIdentifier?: string;
    DBClusterParameterGroupName?: string;
    BackupRetentionPeriod?: number;
    RestoreType?: string;
    Tags?: Array<Tag>;
    EnableCloudwatchLogsExports?: Array<string>;
  };
}

export interface AWS_ApiGatewayV2_Authorizer {
  Type: "AWS::ApiGatewayV2::Authorizer";
  Properties: {
    IdentityValidationExpression?: string;
    AuthorizerUri?: string;
    AuthorizerCredentialsArn?: string;
    AuthorizerType: string;
    JwtConfiguration?: JWTConfiguration;
    AuthorizerResultTtlInSeconds?: number;
    IdentitySource: Array<string>;
    AuthorizerPayloadFormatVersion?: string;
    EnableSimpleResponses?: boolean;
    ApiId: string;
    Name: string;
  };
}

export interface AWS_CloudFormation_WaitConditionHandle {
  Type: "AWS::CloudFormation::WaitConditionHandle";
  Properties: {};
}

export interface AWS_AutoScaling_WarmPool {
  Type: "AWS::AutoScaling::WarmPool";
  Properties: {
    AutoScalingGroupName: string;
    MaxGroupPreparedCapacity?: number;
    MinSize?: number;
    PoolState?: string;
  };
}

export interface AWS_GameLift_GameServerGroup {
  Type: "AWS::GameLift::GameServerGroup";
  Properties: {
    AutoScalingPolicy?: AWS_GameLift_GameServerGroup____AutoScalingPolicy;
    BalancingStrategy?: string;
    DeleteOption?: string;
    GameServerGroupName: string;
    GameServerProtectionPolicy?: string;
    InstanceDefinitions: Array<InstanceDefinition>;
    LaunchTemplate: AWS_GameLift_GameServerGroup____LaunchTemplate;
    MaxSize?: number;
    MinSize?: number;
    RoleArn: string;
    Tags?: Array<Tag>;
    VpcSubnets?: Array<string>;
  };
}

export interface AWS_ElastiCache_GlobalReplicationGroup {
  Type: "AWS::ElastiCache::GlobalReplicationGroup";
  Properties: {
    GlobalReplicationGroupIdSuffix?: string;
    AutomaticFailoverEnabled?: boolean;
    CacheNodeType?: string;
    EngineVersion?: string;
    CacheParameterGroupName?: string;
    GlobalNodeGroupCount?: number;
    GlobalReplicationGroupDescription?: string;
    Members: Array<GlobalReplicationGroupMember>;
    RegionalConfigurations?: Array<RegionalConfiguration>;
  };
}

export interface AWS_SageMaker_Image {
  Type: "AWS::SageMaker::Image";
  Properties: {
    ImageName: string;
    ImageRoleArn: string;
    ImageDisplayName?: string;
    ImageDescription?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_SSM_MaintenanceWindow {
  Type: "AWS::SSM::MaintenanceWindow";
  Properties: {
    StartDate?: string;
    Description?: string;
    AllowUnassociatedTargets: boolean;
    Cutoff: number;
    Schedule: string;
    Duration: number;
    ScheduleOffset?: number;
    EndDate?: string;
    Tags?: Array<Tag>;
    Name: string;
    ScheduleTimezone?: string;
  };
}

export interface AWS_CloudFormation_Macro {
  Type: "AWS::CloudFormation::Macro";
  Properties: {
    Description?: string;
    FunctionName: string;
    LogGroupName?: string;
    LogRoleARN?: string;
    Name: string;
  };
}

export interface AWS_EC2_TransitGatewayMulticastDomain {
  Type: "AWS::EC2::TransitGatewayMulticastDomain";
  Properties: {
    TransitGatewayId: string;
    Tags?: Array<Tag>;
    Options?: any;
  };
}

export interface AWS_Route53_RecordSetGroup {
  Type: "AWS::Route53::RecordSetGroup";
  Properties: {
    Comment?: string;
    HostedZoneId?: string;
    HostedZoneName?: string;
    RecordSets?: Array<RecordSet>;
  };
}

export interface AWS_KinesisFirehose_DeliveryStream {
  Type: "AWS::KinesisFirehose::DeliveryStream";
  Properties: {
    DeliveryStreamEncryptionConfigurationInput?: DeliveryStreamEncryptionConfigurationInput;
    DeliveryStreamName?: string;
    DeliveryStreamType?: string;
    ElasticsearchDestinationConfiguration?: ElasticsearchDestinationConfiguration;
    ExtendedS3DestinationConfiguration?: ExtendedS3DestinationConfiguration;
    KinesisStreamSourceConfiguration?: KinesisStreamSourceConfiguration;
    RedshiftDestinationConfiguration?: RedshiftDestinationConfiguration;
    S3DestinationConfiguration?: AWS_KinesisFirehose_DeliveryStream____S3DestinationConfiguration;
    SplunkDestinationConfiguration?: SplunkDestinationConfiguration;
    HttpEndpointDestinationConfiguration?: HttpEndpointDestinationConfiguration;
    Tags?: Array<Tag>;
  };
}

export interface AWS_S3Outposts_BucketPolicy {
  Type: "AWS::S3Outposts::BucketPolicy";
  Properties: {
    Bucket: string;
    PolicyDocument: any;
  };
}

export interface AWS_IAM_ManagedPolicy {
  Type: "AWS::IAM::ManagedPolicy";
  Properties: {
    Description?: string;
    Groups?: Array<string>;
    ManagedPolicyName?: string;
    Path?: string;
    PolicyDocument: any;
    Roles?: Array<string>;
    Users?: Array<string>;
  };
}

export interface AWS_Greengrass_DeviceDefinitionVersion {
  Type: "AWS::Greengrass::DeviceDefinitionVersion";
  Properties: {
    DeviceDefinitionId: string;
    Devices: Array<AWS_Greengrass_DeviceDefinitionVersion____Device>;
  };
}

export interface AWS_IoT_PolicyPrincipalAttachment {
  Type: "AWS::IoT::PolicyPrincipalAttachment";
  Properties: {
    PolicyName: string;
    Principal: string;
  };
}

export interface AWS_Glue_Registry {
  Type: "AWS::Glue::Registry";
  Properties: {
    Name: string;
    Description?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ApplicationAutoScaling_ScalableTarget {
  Type: "AWS::ApplicationAutoScaling::ScalableTarget";
  Properties: {
    MaxCapacity: number;
    MinCapacity: number;
    ResourceId: string;
    RoleARN: string;
    ScalableDimension: string;
    ScheduledActions?: Array<ScheduledAction>;
    ServiceNamespace: string;
    SuspendedState?: SuspendedState;
  };
}

export interface AWS_Config_ConformancePack {
  Type: "AWS::Config::ConformancePack";
  Properties: {
    ConformancePackName: string;
    DeliveryS3Bucket?: string;
    DeliveryS3KeyPrefix?: string;
    TemplateBody?: string;
    TemplateS3Uri?: string;
    ConformancePackInputParameters?: Array<AWS_Config_ConformancePack____ConformancePackInputParameter>;
  };
}

export interface AWS_DevOpsGuru_ResourceCollection {
  Type: "AWS::DevOpsGuru::ResourceCollection";
  Properties: {
    ResourceCollectionFilter: ResourceCollectionFilter;
  };
}

export interface AWS_Amplify_Domain {
  Type: "AWS::Amplify::Domain";
  Properties: {
    SubDomainSettings: Array<SubDomainSetting>;
    AppId: string;
    AutoSubDomainIAMRole?: string;
    DomainName: string;
    EnableAutoSubDomain?: boolean;
    AutoSubDomainCreationPatterns?: Array<string>;
  };
}

export interface AWS_ECS_ClusterCapacityProviderAssociations {
  Type: "AWS::ECS::ClusterCapacityProviderAssociations";
  Properties: {
    CapacityProviders: Array<string>;
    Cluster: string;
    DefaultCapacityProviderStrategy: Array<CapacityProviderStrategy>;
  };
}

export interface AWS_Route53Resolver_ResolverRuleAssociation {
  Type: "AWS::Route53Resolver::ResolverRuleAssociation";
  Properties: {
    VPCId: string;
    ResolverRuleId: string;
    Name?: string;
  };
}

export interface AWS_Greengrass_SubscriptionDefinition {
  Type: "AWS::Greengrass::SubscriptionDefinition";
  Properties: {
    InitialVersion?: SubscriptionDefinitionVersion;
    Tags?: any;
    Name: string;
  };
}

export interface AWS_IoTEvents_DetectorModel {
  Type: "AWS::IoTEvents::DetectorModel";
  Properties: {
    DetectorModelDefinition: DetectorModelDefinition;
    DetectorModelDescription?: string;
    DetectorModelName?: string;
    EvaluationMethod?: string;
    Key?: string;
    RoleArn: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ApiGateway_VpcLink {
  Type: "AWS::ApiGateway::VpcLink";
  Properties: {
    Description?: string;
    TargetArns: Array<string>;
    Name: string;
  };
}

export interface AWS_ECR_RegistryPolicy {
  Type: "AWS::ECR::RegistryPolicy";
  Properties: {
    PolicyText: any;
  };
}

export interface AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource {
  Type: "AWS::KinesisAnalyticsV2::ApplicationReferenceDataSource";
  Properties: {
    ApplicationName: string;
    ReferenceDataSource: AWS_KinesisAnalyticsV2_ApplicationReferenceDataSource____ReferenceDataSource;
  };
}

export interface AWS_ApiGateway_Method {
  Type: "AWS::ApiGateway::Method";
  Properties: {
    ApiKeyRequired?: boolean;
    AuthorizationScopes?: Array<string>;
    AuthorizationType?: string;
    AuthorizerId?: string;
    HttpMethod: string;
    Integration?: Integration;
    MethodResponses?: Array<MethodResponse>;
    OperationName?: string;
    RequestModels?: Record<string, string>;
    RequestParameters?: Record<string, boolean>;
    RequestValidatorId?: string;
    ResourceId: string;
    RestApiId: string;
  };
}

export interface AWS_DMS_Endpoint {
  Type: "AWS::DMS::Endpoint";
  Properties: {
    SybaseSettings?: SybaseSettings;
    OracleSettings?: OracleSettings;
    KafkaSettings?: KafkaSettings;
    Port?: number;
    MySqlSettings?: MySqlSettings;
    S3Settings?: S3Settings;
    ResourceIdentifier?: string;
    KinesisSettings?: KinesisSettings;
    SslMode?: string;
    RedshiftSettings?: RedshiftSettings;
    EndpointType: string;
    Tags?: Array<Tag>;
    Password?: string;
    MongoDbSettings?: MongoDbSettings;
    IbmDb2Settings?: IbmDb2Settings;
    KmsKeyId?: string;
    DatabaseName?: string;
    NeptuneSettings?: NeptuneSettings;
    ElasticsearchSettings?: ElasticsearchSettings;
    EngineName: string;
    DocDbSettings?: DocDbSettings;
    DynamoDbSettings?: DynamoDbSettings;
    Username?: string;
    MicrosoftSqlServerSettings?: MicrosoftSqlServerSettings;
    ServerName?: string;
    ExtraConnectionAttributes?: string;
    EndpointIdentifier?: string;
    CertificateArn?: string;
    PostgreSqlSettings?: PostgreSqlSettings;
  };
}

export interface AWS_ServiceCatalog_LaunchNotificationConstraint {
  Type: "AWS::ServiceCatalog::LaunchNotificationConstraint";
  Properties: {
    Description?: string;
    NotificationArns: Array<string>;
    AcceptLanguage?: string;
    PortfolioId: string;
    ProductId: string;
  };
}

export interface AWS_DirectoryService_SimpleAD {
  Type: "AWS::DirectoryService::SimpleAD";
  Properties: {
    CreateAlias?: boolean;
    Description?: string;
    EnableSso?: boolean;
    Name: string;
    Password: string;
    ShortName?: string;
    Size: string;
    VpcSettings: AWS_DirectoryService_SimpleAD____VpcSettings;
  };
}

export interface AWS_EC2_VolumeAttachment {
  Type: "AWS::EC2::VolumeAttachment";
  Properties: {
    Device: string;
    InstanceId: string;
    VolumeId: string;
  };
}

export interface AWS_SecretsManager_SecretTargetAttachment {
  Type: "AWS::SecretsManager::SecretTargetAttachment";
  Properties: {
    SecretId: string;
    TargetType: string;
    TargetId: string;
  };
}

export interface AWS_Greengrass_ResourceDefinitionVersion {
  Type: "AWS::Greengrass::ResourceDefinitionVersion";
  Properties: {
    Resources: Array<AWS_Greengrass_ResourceDefinitionVersion____ResourceInstance>;
    ResourceDefinitionId: string;
  };
}

export interface AWS_EC2_NetworkInsightsAnalysis {
  Type: "AWS::EC2::NetworkInsightsAnalysis";
  Properties: {
    NetworkInsightsPathId: string;
    FilterInArns?: Array<string>;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_Host {
  Type: "AWS::EC2::Host";
  Properties: {
    AutoPlacement?: string;
    AvailabilityZone: string;
    HostRecovery?: string;
    InstanceType: string;
  };
}

export interface AWS_ECS_TaskDefinition {
  Type: "AWS::ECS::TaskDefinition";
  Properties: {
    Family?: string;
    ContainerDefinitions?: Array<AWS_ECS_TaskDefinition____ContainerDefinition>;
    Cpu?: string;
    ExecutionRoleArn?: string;
    EphemeralStorage?: EphemeralStorage;
    InferenceAccelerators?: Array<InferenceAccelerator>;
    Memory?: string;
    NetworkMode?: string;
    PlacementConstraints?: Array<TaskDefinitionPlacementConstraint>;
    ProxyConfiguration?: ProxyConfiguration;
    RequiresCompatibilities?: Array<string>;
    TaskRoleArn?: string;
    Volumes?: Array<AWS_ECS_TaskDefinition____Volume>;
    PidMode?: string;
    IpcMode?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ApiGatewayV2_IntegrationResponse {
  Type: "AWS::ApiGatewayV2::IntegrationResponse";
  Properties: {
    ResponseTemplates?: any;
    TemplateSelectionExpression?: string;
    ResponseParameters?: any;
    ContentHandlingStrategy?: string;
    IntegrationId: string;
    IntegrationResponseKey: string;
    ApiId: string;
  };
}

export interface AWS_IAM_ServerCertificate {
  Type: "AWS::IAM::ServerCertificate";
  Properties: {
    CertificateBody?: string;
    CertificateChain?: string;
    ServerCertificateName?: string;
    Path?: string;
    PrivateKey?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_NetworkManager_Site {
  Type: "AWS::NetworkManager::Site";
  Properties: {
    Description?: string;
    Tags?: Array<Tag>;
    GlobalNetworkId: string;
    Location?: AWS_NetworkManager_Site____Location;
  };
}

export interface AWS_ElastiCache_CacheCluster {
  Type: "AWS::ElastiCache::CacheCluster";
  Properties: {
    AZMode?: string;
    AutoMinorVersionUpgrade?: boolean;
    CacheNodeType: string;
    CacheParameterGroupName?: string;
    CacheSecurityGroupNames?: Array<string>;
    CacheSubnetGroupName?: string;
    ClusterName?: string;
    Engine: string;
    EngineVersion?: string;
    LogDeliveryConfigurations?: Array<AWS_ElastiCache_CacheCluster____LogDeliveryConfigurationRequest>;
    NotificationTopicArn?: string;
    NumCacheNodes: number;
    Port?: number;
    PreferredAvailabilityZone?: string;
    PreferredAvailabilityZones?: Array<string>;
    PreferredMaintenanceWindow?: string;
    SnapshotArns?: Array<string>;
    SnapshotName?: string;
    SnapshotRetentionLimit?: number;
    SnapshotWindow?: string;
    Tags?: Array<Tag>;
    VpcSecurityGroupIds?: Array<string>;
  };
}

export interface AWS_IoT_ThingPrincipalAttachment {
  Type: "AWS::IoT::ThingPrincipalAttachment";
  Properties: {
    Principal: string;
    ThingName: string;
  };
}

export interface AWS_SageMaker_Device {
  Type: "AWS::SageMaker::Device";
  Properties: {
    DeviceFleetName: string;
    Device?: any;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Cognito_UserPoolDomain {
  Type: "AWS::Cognito::UserPoolDomain";
  Properties: {
    UserPoolId: string;
    CustomDomainConfig?: CustomDomainConfigType;
    Domain: string;
  };
}

export interface AWS_DocDB_DBClusterParameterGroup {
  Type: "AWS::DocDB::DBClusterParameterGroup";
  Properties: {
    Description: string;
    Parameters: any;
    Family: string;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_Signer_ProfilePermission {
  Type: "AWS::Signer::ProfilePermission";
  Properties: {
    ProfileName: string;
    ProfileVersion?: string;
    Action: string;
    Principal: string;
    StatementId: string;
  };
}

export interface AWS_CloudFormation_ModuleDefaultVersion {
  Type: "AWS::CloudFormation::ModuleDefaultVersion";
  Properties: {
    Arn?: string;
    ModuleName?: string;
    VersionId?: string;
  };
}

export interface AWS_ElasticBeanstalk_ApplicationVersion {
  Type: "AWS::ElasticBeanstalk::ApplicationVersion";
  Properties: {
    ApplicationName: string;
    Description?: string;
    SourceBundle: SourceBundle;
  };
}

export interface AWS_MSK_Cluster {
  Type: "AWS::MSK::Cluster";
  Properties: {
    BrokerNodeGroupInfo: BrokerNodeGroupInfo;
    EnhancedMonitoring?: string;
    KafkaVersion: string;
    NumberOfBrokerNodes: number;
    EncryptionInfo?: EncryptionInfo;
    OpenMonitoring?: OpenMonitoring;
    ClusterName: string;
    ClientAuthentication?: ClientAuthentication;
    LoggingInfo?: AWS_MSK_Cluster____LoggingInfo;
    Tags?: any;
    ConfigurationInfo?: ConfigurationInfo;
  };
}

export interface AWS_EC2_VPCEndpoint {
  Type: "AWS::EC2::VPCEndpoint";
  Properties: {
    PolicyDocument?: any;
    PrivateDnsEnabled?: boolean;
    RouteTableIds?: Array<string>;
    SecurityGroupIds?: Array<string>;
    ServiceName: string;
    SubnetIds?: Array<string>;
    VpcEndpointType?: string;
    VpcId: string;
  };
}

export interface AWS_IoT_TopicRuleDestination {
  Type: "AWS::IoT::TopicRuleDestination";
  Properties: {
    Status?: string;
    HttpUrlProperties?: HttpUrlDestinationSummary;
    VpcProperties?: VpcDestinationProperties;
  };
}

export interface AWS_ElasticLoadBalancingV2_TargetGroup {
  Type: "AWS::ElasticLoadBalancingV2::TargetGroup";
  Properties: {
    HealthCheckEnabled?: boolean;
    HealthCheckIntervalSeconds?: number;
    HealthCheckPath?: string;
    HealthCheckPort?: string;
    HealthCheckProtocol?: string;
    HealthCheckTimeoutSeconds?: number;
    HealthyThresholdCount?: number;
    Matcher?: Matcher;
    Name?: string;
    Port?: number;
    Protocol?: string;
    ProtocolVersion?: string;
    Tags?: Array<Tag>;
    TargetGroupAttributes?: Array<TargetGroupAttribute>;
    TargetType?: string;
    Targets?: Array<TargetDescription>;
    UnhealthyThresholdCount?: number;
    VpcId?: string;
  };
}

export interface AWS_ImageBuilder_ContainerRecipe {
  Type: "AWS::ImageBuilder::ContainerRecipe";
  Properties: {
    Name: string;
    Description?: string;
    Version: string;
    Components: Array<AWS_ImageBuilder_ContainerRecipe____ComponentConfiguration>;
    InstanceConfiguration?: any;
    DockerfileTemplateData?: string;
    DockerfileTemplateUri?: string;
    PlatformOverride?: string;
    ContainerType: string;
    ImageOsVersionOverride?: string;
    TargetRepository: TargetContainerRepository;
    KmsKeyId?: string;
    ParentImage: string;
    WorkingDirectory?: string;
    Tags?: Record<string, string>;
  };
}

export interface AWS_RoboMaker_Robot {
  Type: "AWS::RoboMaker::Robot";
  Properties: {
    Fleet?: string;
    Architecture: string;
    GreengrassGroupId: string;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_EC2_VPCGatewayAttachment {
  Type: "AWS::EC2::VPCGatewayAttachment";
  Properties: {
    InternetGatewayId?: string;
    VpcId: string;
    VpnGatewayId?: string;
  };
}

export interface AWS_DataSync_LocationSMB {
  Type: "AWS::DataSync::LocationSMB";
  Properties: {
    AgentArns: Array<string>;
    Domain?: string;
    MountOptions?: AWS_DataSync_LocationSMB____MountOptions;
    Password: string;
    ServerHostname: string;
    Subdirectory: string;
    User: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EFS_AccessPoint {
  Type: "AWS::EFS::AccessPoint";
  Properties: {
    ClientToken?: string;
    AccessPointTags?: Array<AccessPointTag>;
    FileSystemId: string;
    PosixUser?: PosixUser;
    RootDirectory?: RootDirectory;
  };
}

export interface AWS_Glue_Trigger {
  Type: "AWS::Glue::Trigger";
  Properties: {
    Type: string;
    StartOnCreation?: boolean;
    Description?: string;
    Actions: Array<AWS_Glue_Trigger____Action>;
    WorkflowName?: string;
    Schedule?: string;
    Tags?: any;
    Name?: string;
    Predicate?: AWS_Glue_Trigger____Predicate;
  };
}

export interface AWS_EC2_VPCCidrBlock {
  Type: "AWS::EC2::VPCCidrBlock";
  Properties: {
    AmazonProvidedIpv6CidrBlock?: boolean;
    CidrBlock?: string;
    VpcId: string;
  };
}

export interface AWS_SSM_Parameter {
  Type: "AWS::SSM::Parameter";
  Properties: {
    Type: string;
    Description?: string;
    Policies?: string;
    AllowedPattern?: string;
    Tier?: string;
    Value: string;
    DataType?: string;
    Tags?: any;
    Name?: string;
  };
}

export interface AWS_Inspector_AssessmentTemplate {
  Type: "AWS::Inspector::AssessmentTemplate";
  Properties: {
    AssessmentTargetArn: string;
    DurationInSeconds: number;
    AssessmentTemplateName?: string;
    RulesPackageArns: Array<string>;
    UserAttributesForFindings?: Array<Tag>;
  };
}

export interface AWS_AppMesh_Mesh {
  Type: "AWS::AppMesh::Mesh";
  Properties: {
    MeshName?: string;
    Spec?: MeshSpec;
    Tags?: Array<Tag>;
  };
}

export interface AWS_RDS_DBProxyTargetGroup {
  Type: "AWS::RDS::DBProxyTargetGroup";
  Properties: {
    DBProxyName: string;
    TargetGroupName: string;
    ConnectionPoolConfigurationInfo?: ConnectionPoolConfigurationInfoFormat;
    DBInstanceIdentifiers?: Array<string>;
    DBClusterIdentifiers?: Array<string>;
  };
}

export interface AWS_KinesisAnalytics_ApplicationReferenceDataSource {
  Type: "AWS::KinesisAnalytics::ApplicationReferenceDataSource";
  Properties: {
    ApplicationName: string;
    ReferenceDataSource: AWS_KinesisAnalytics_ApplicationReferenceDataSource____ReferenceDataSource;
  };
}

export interface AWS_SSM_ResourceDataSync {
  Type: "AWS::SSM::ResourceDataSync";
  Properties: {
    S3Destination?: S3Destination;
    KMSKeyArn?: string;
    SyncSource?: SyncSource;
    BucketName?: string;
    BucketRegion?: string;
    SyncFormat?: string;
    SyncName: string;
    SyncType?: string;
    BucketPrefix?: string;
  };
}

export interface AWS_AppConfig_Application {
  Type: "AWS::AppConfig::Application";
  Properties: {
    Description?: string;
    Tags?: Array<AWS_AppConfig_Application____Tags>;
    Name: string;
  };
}

export interface AWS_KinesisAnalytics_Application {
  Type: "AWS::KinesisAnalytics::Application";
  Properties: {
    ApplicationName?: string;
    Inputs: Array<AWS_KinesisAnalytics_Application____Input>;
    ApplicationDescription?: string;
    ApplicationCode?: string;
  };
}

export interface AWS_DynamoDB_Table {
  Type: "AWS::DynamoDB::Table";
  Properties: {
    AttributeDefinitions?: Array<AttributeDefinition>;
    BillingMode?: string;
    ContributorInsightsSpecification?: ContributorInsightsSpecification;
    GlobalSecondaryIndexes?: Array<GlobalSecondaryIndex>;
    KeySchema: Array<KeySchema>;
    KinesisStreamSpecification?: KinesisStreamSpecification;
    LocalSecondaryIndexes?: Array<LocalSecondaryIndex>;
    PointInTimeRecoverySpecification?: PointInTimeRecoverySpecification;
    ProvisionedThroughput?: AWS_DynamoDB_Table____ProvisionedThroughput;
    SSESpecification?: SSESpecification;
    StreamSpecification?: StreamSpecification;
    TableName?: string;
    Tags?: Array<Tag>;
    TimeToLiveSpecification?: TimeToLiveSpecification;
  };
}

export interface AWS_EC2_EC2Fleet {
  Type: "AWS::EC2::EC2Fleet";
  Properties: {
    TargetCapacitySpecification: TargetCapacitySpecificationRequest;
    OnDemandOptions?: OnDemandOptionsRequest;
    Type?: string;
    ExcessCapacityTerminationPolicy?: string;
    TagSpecifications?: Array<AWS_EC2_EC2Fleet____TagSpecification>;
    SpotOptions?: SpotOptionsRequest;
    ValidFrom?: string;
    ReplaceUnhealthyInstances?: boolean;
    LaunchTemplateConfigs: Array<FleetLaunchTemplateConfigRequest>;
    TerminateInstancesWithExpiration?: boolean;
    ValidUntil?: string;
  };
}

export interface AWS_Cassandra_Table {
  Type: "AWS::Cassandra::Table";
  Properties: {
    KeyspaceName: string;
    TableName?: string;
    RegularColumns?: Array<AWS_Cassandra_Table____Column>;
    PartitionKeyColumns: Array<AWS_Cassandra_Table____Column>;
    ClusteringKeyColumns?: Array<ClusteringKeyColumn>;
    BillingMode?: BillingMode;
    PointInTimeRecoveryEnabled?: boolean;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Greengrass_GroupVersion {
  Type: "AWS::Greengrass::GroupVersion";
  Properties: {
    LoggerDefinitionVersionArn?: string;
    DeviceDefinitionVersionArn?: string;
    FunctionDefinitionVersionArn?: string;
    CoreDefinitionVersionArn?: string;
    ResourceDefinitionVersionArn?: string;
    ConnectorDefinitionVersionArn?: string;
    SubscriptionDefinitionVersionArn?: string;
    GroupId: string;
  };
}

export interface AWS_Lambda_Permission {
  Type: "AWS::Lambda::Permission";
  Properties: {
    Action: string;
    EventSourceToken?: string;
    FunctionName: string;
    Principal: string;
    SourceAccount?: string;
    SourceArn?: string;
  };
}

export interface AWS_Logs_QueryDefinition {
  Type: "AWS::Logs::QueryDefinition";
  Properties: {
    Name: string;
    QueryString: string;
    LogGroupNames?: Array<string>;
  };
}

export interface AWS_GuardDuty_IPSet {
  Type: "AWS::GuardDuty::IPSet";
  Properties: {
    Format: string;
    Activate: boolean;
    DetectorId: string;
    Name?: string;
    Location: string;
  };
}

export interface AWS_IoT_Certificate {
  Type: "AWS::IoT::Certificate";
  Properties: {
    CACertificatePem?: string;
    CertificatePem?: string;
    CertificateSigningRequest?: string;
    CertificateMode?: string;
    Status: string;
  };
}

export interface AWS_CertificateManager_Account {
  Type: "AWS::CertificateManager::Account";
  Properties: {
    ExpiryEventsConfiguration: ExpiryEventsConfiguration;
  };
}

export interface AWS_SSM_Association {
  Type: "AWS::SSM::Association";
  Properties: {
    AssociationName?: string;
    DocumentVersion?: string;
    InstanceId?: string;
    Name: string;
    Parameters?: Record<string, any>;
    ScheduleExpression?: string;
    Targets?: Array<AWS_SSM_Association____Target>;
    OutputLocation?: InstanceAssociationOutputLocation;
    AutomationTargetParameterName?: string;
    MaxErrors?: string;
    MaxConcurrency?: string;
    ComplianceSeverity?: string;
    SyncCompliance?: string;
    WaitForSuccessTimeoutSeconds?: number;
    ApplyOnlyAtCronInterval?: boolean;
  };
}

export interface AWS_ImageBuilder_ImageRecipe {
  Type: "AWS::ImageBuilder::ImageRecipe";
  Properties: {
    Name: string;
    Description?: string;
    Version: string;
    Components: Array<AWS_ImageBuilder_ImageRecipe____ComponentConfiguration>;
    BlockDeviceMappings?: Array<AWS_ImageBuilder_ImageRecipe____InstanceBlockDeviceMapping>;
    ParentImage: string;
    WorkingDirectory?: string;
    Tags?: Record<string, string>;
  };
}

export interface AWS_CodeStar_GitHubRepository {
  Type: "AWS::CodeStar::GitHubRepository";
  Properties: {
    EnableIssues?: boolean;
    ConnectionArn?: string;
    RepositoryName: string;
    RepositoryAccessToken?: string;
    RepositoryOwner: string;
    IsPrivate?: boolean;
    Code?: AWS_CodeStar_GitHubRepository____Code;
    RepositoryDescription?: string;
  };
}

export interface AWS_Athena_NamedQuery {
  Type: "AWS::Athena::NamedQuery";
  Properties: {
    Name?: string;
    Database: string;
    Description?: string;
    QueryString: string;
    WorkGroup?: string;
  };
}

export interface AWS_CloudFormation_ModuleVersion {
  Type: "AWS::CloudFormation::ModuleVersion";
  Properties: {
    ModuleName: string;
    ModulePackage: string;
  };
}

export interface AWS_Chatbot_SlackChannelConfiguration {
  Type: "AWS::Chatbot::SlackChannelConfiguration";
  Properties: {
    SlackWorkspaceId: string;
    SlackChannelId: string;
    ConfigurationName: string;
    IamRoleArn: string;
    SnsTopicArns?: Array<string>;
    LoggingLevel?: string;
  };
}

export interface AWS_Inspector_AssessmentTarget {
  Type: "AWS::Inspector::AssessmentTarget";
  Properties: {
    AssessmentTargetName?: string;
    ResourceGroupArn?: string;
  };
}

export interface AWS_AutoScaling_AutoScalingGroup {
  Type: "AWS::AutoScaling::AutoScalingGroup";
  Properties: {
    AutoScalingGroupName?: string;
    AvailabilityZones?: Array<string>;
    CapacityRebalance?: boolean;
    Cooldown?: string;
    DesiredCapacity?: string;
    HealthCheckGracePeriod?: number;
    HealthCheckType?: string;
    InstanceId?: string;
    LaunchConfigurationName?: string;
    LaunchTemplate?: AWS_AutoScaling_AutoScalingGroup____LaunchTemplateSpecification;
    LifecycleHookSpecificationList?: Array<LifecycleHookSpecification>;
    LoadBalancerNames?: Array<string>;
    MaxInstanceLifetime?: number;
    MaxSize: string;
    MetricsCollection?: Array<MetricsCollection>;
    MinSize: string;
    MixedInstancesPolicy?: MixedInstancesPolicy;
    NewInstancesProtectedFromScaleIn?: boolean;
    NotificationConfigurations?: Array<AWS_AutoScaling_AutoScalingGroup____NotificationConfiguration>;
    PlacementGroup?: string;
    ServiceLinkedRoleARN?: string;
    Tags?: Array<TagProperty>;
    TargetGroupARNs?: Array<string>;
    TerminationPolicies?: Array<string>;
    VPCZoneIdentifier?: Array<string>;
  };
}

export interface AWS_FraudDetector_Variable {
  Type: "AWS::FraudDetector::Variable";
  Properties: {
    Name: string;
    DataSource: string;
    DataType: string;
    DefaultValue: string;
    Description?: string;
    Tags?: Array<Tag>;
    VariableType?: string;
  };
}

export interface AWS_EventSchemas_Registry {
  Type: "AWS::EventSchemas::Registry";
  Properties: {
    Description?: string;
    RegistryName?: string;
    Tags?: Array<AWS_EventSchemas_Registry____TagsEntry>;
  };
}

export interface AWS_QuickSight_Theme {
  Type: "AWS::QuickSight::Theme";
  Properties: {
    AwsAccountId: string;
    BaseThemeId?: string;
    Configuration?: ThemeConfiguration;
    Name?: string;
    Permissions?: Array<AWS_QuickSight_Theme____ResourcePermission>;
    Tags?: Array<Tag>;
    ThemeId: string;
    VersionDescription?: string;
  };
}

export interface AWS_Route53Resolver_ResolverEndpoint {
  Type: "AWS::Route53Resolver::ResolverEndpoint";
  Properties: {
    IpAddresses: Array<IpAddressRequest>;
    Direction: string;
    SecurityGroupIds: Array<string>;
    Tags?: Array<Tag>;
    Name?: string;
  };
}

export interface AWS_ImageBuilder_Image {
  Type: "AWS::ImageBuilder::Image";
  Properties: {
    ImageTestsConfiguration?: AWS_ImageBuilder_Image____ImageTestsConfiguration;
    ImageRecipeArn?: string;
    ContainerRecipeArn?: string;
    DistributionConfigurationArn?: string;
    InfrastructureConfigurationArn: string;
    EnhancedImageMetadataEnabled?: boolean;
    Tags?: Record<string, string>;
  };
}

export interface AWS_SSO_InstanceAccessControlAttributeConfiguration {
  Type: "AWS::SSO::InstanceAccessControlAttributeConfiguration";
  Properties: {
    InstanceArn: string;
    AccessControlAttributes?: Array<AccessControlAttribute>;
  };
}

export interface AWS_Cassandra_Keyspace {
  Type: "AWS::Cassandra::Keyspace";
  Properties: {
    KeyspaceName?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_VPCDHCPOptionsAssociation {
  Type: "AWS::EC2::VPCDHCPOptionsAssociation";
  Properties: {
    DhcpOptionsId: string;
    VpcId: string;
  };
}

export interface AWS_DMS_ReplicationTask {
  Type: "AWS::DMS::ReplicationTask";
  Properties: {
    ReplicationTaskSettings?: string;
    CdcStartPosition?: string;
    CdcStopPosition?: string;
    MigrationType: string;
    TargetEndpointArn: string;
    ReplicationInstanceArn: string;
    TaskData?: string;
    CdcStartTime?: number;
    ResourceIdentifier?: string;
    TableMappings: string;
    ReplicationTaskIdentifier?: string;
    SourceEndpointArn: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_EC2_EnclaveCertificateIamRoleAssociation {
  Type: "AWS::EC2::EnclaveCertificateIamRoleAssociation";
  Properties: {
    CertificateArn: string;
    RoleArn: string;
  };
}

export interface AWS_ServiceDiscovery_PublicDnsNamespace {
  Type: "AWS::ServiceDiscovery::PublicDnsNamespace";
  Properties: {
    Description?: string;
    Tags?: Array<Tag>;
    Name: string;
  };
}

export interface AWS_RDS_DBProxyEndpoint {
  Type: "AWS::RDS::DBProxyEndpoint";
  Properties: {
    DBProxyEndpointName: string;
    DBProxyName: string;
    VpcSecurityGroupIds?: Array<string>;
    VpcSubnetIds: Array<string>;
    TargetRole?: string;
    Tags?: Array<AWS_RDS_DBProxyEndpoint____TagFormat>;
  };
}

export interface AWS_EC2_TrafficMirrorTarget {
  Type: "AWS::EC2::TrafficMirrorTarget";
  Properties: {
    NetworkLoadBalancerArn?: string;
    Description?: string;
    NetworkInterfaceId?: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Config_StoredQuery {
  Type: "AWS::Config::StoredQuery";
  Properties: {
    QueryName: string;
    QueryDescription?: string;
    QueryExpression: string;
    Tags?: Array<Tag>;
  };
}

export interface AWS_Glue_SecurityConfiguration {
  Type: "AWS::Glue::SecurityConfiguration";
  Properties: {
    EncryptionConfiguration: AWS_Glue_SecurityConfiguration____EncryptionConfiguration;
    Name: string;
  };
}

export interface AWS_DMS_ReplicationInstance {
  Type: "AWS::DMS::ReplicationInstance";
  Properties: {
    ReplicationInstanceIdentifier?: string;
    EngineVersion?: string;
    KmsKeyId?: string;
    AvailabilityZone?: string;
    PreferredMaintenanceWindow?: string;
    AutoMinorVersionUpgrade?: boolean;
    ReplicationSubnetGroupIdentifier?: string;
    AllocatedStorage?: number;
    ResourceIdentifier?: string;
    VpcSecurityGroupIds?: Array<string>;
    AllowMajorVersionUpgrade?: boolean;
    ReplicationInstanceClass: string;
    PubliclyAccessible?: boolean;
    MultiAZ?: boolean;
    Tags?: Array<Tag>;
  };
}

export interface AWS_ApiGatewayV2_ApiMapping {
  Type: "AWS::ApiGatewayV2::ApiMapping";
  Properties: {
    DomainName: string;
    Stage: string;
    ApiMappingKey?: string;
    ApiId: string;
  };
}

export interface AWS_AutoScaling_ScheduledAction {
  Type: "AWS::AutoScaling::ScheduledAction";
  Properties: {
    AutoScalingGroupName: string;
    DesiredCapacity?: number;
    EndTime?: string;
    MaxSize?: number;
    MinSize?: number;
    Recurrence?: string;
    StartTime?: string;
  };
}
