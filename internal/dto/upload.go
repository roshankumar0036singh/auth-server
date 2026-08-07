package dto

type UploadURLRequest struct {
	FileName string `json:"fileName" binding:"required"`
}

type UploadURLResponse struct {
	UploadURL string `json:"uploadUrl"`
	FileURL   string `json:"fileUrl"`
}