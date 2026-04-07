package model

// AssetType classifies the kind of asset discovered on the network.
type AssetType string

const (
	AssetTypeServer         AssetType = "server"
	AssetTypeWorkstation    AssetType = "workstation"
	AssetTypeNetworkDevice  AssetType = "network_device"
	AssetTypeCloudInstance  AssetType = "cloud_instance"
	AssetTypeContainer      AssetType = "container"
	AssetTypeVirtualMachine AssetType = "virtual_machine"
	AssetTypeIOTDevice      AssetType = "iot_device"
	AssetTypeAppliance      AssetType = "appliance"
)

// Valid returns true when the AssetType is one of the recognised values.
func (a AssetType) Valid() bool {
	switch a {
	case AssetTypeServer,
		AssetTypeWorkstation,
		AssetTypeNetworkDevice,
		AssetTypeCloudInstance,
		AssetTypeContainer,
		AssetTypeVirtualMachine,
		AssetTypeIOTDevice,
		AssetTypeAppliance:
		return true
	default:
		return false
	}
}

// AuthorizationState indicates whether an asset is authorised to be on the network.
type AuthorizationState string

const (
	AuthorizationUnknown      AuthorizationState = "unknown"
	AuthorizationAuthorized   AuthorizationState = "authorized"
	AuthorizationUnauthorized AuthorizationState = "unauthorized"
)

// ManagedState indicates whether an asset is under management by the organisation.
type ManagedState string

const (
	ManagedUnknown   ManagedState = "unknown"
	ManagedManaged   ManagedState = "managed"
	ManagedUnmanaged ManagedState = "unmanaged"
)

// Severity represents the impact level assigned to an event or finding.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// EventType identifies the kind of lifecycle event recorded for an asset.
type EventType string

const (
	EventAssetDiscovered          EventType = "AssetDiscovered"
	EventAssetUpdated             EventType = "AssetUpdated"
	EventUnauthorizedAssetDetected EventType = "UnauthorizedAssetDetected"
	EventUnmanagedAssetDetected   EventType = "UnmanagedAssetDetected"
	EventAssetNotSeen             EventType = "AssetNotSeen"
	EventAssetRemoved             EventType = "AssetRemoved"
)

// ScanStatus tracks the lifecycle state of a scan run.
type ScanStatus string

const (
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusTimedOut  ScanStatus = "timed_out"
)
