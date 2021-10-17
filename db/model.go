package db

type Poc struct {
	Id           int    `json:"id"`
	Name         string `json:"name"`
	Remarks      string `json:"remarks"`
	Level        int    `json:"level"`
	Type         string `json:"type"`
	Author       string `json:"author"`
	ReferenceUrl string `json:"reference_url"`
	ReferenceCVE string `json:"reference_cve"`
}
