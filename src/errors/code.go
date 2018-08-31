package errors

const (
	ErrorTypeInternalErr        uint32 = 1
	ErrorTypeEncodingErr        uint32 = 2
	ErrorTypeUnauthorized       uint32 = 3
	ErrorTypeUnknownRequest     uint32 = 4
	ErrorTypeUnknownAddress     uint32 = 5
	ErrorTypeBaseUnknownAddress uint32 = 5 // lol fuck it
	ErrorTypeBadNonce           uint32 = 6

	ErrorTypeBaseInvalidInput  uint32 = 20
	ErrorTypeBaseInvalidOutput uint32 = 21

	ErrorTypeLowGasPriceErr        uint32 = 101
)
