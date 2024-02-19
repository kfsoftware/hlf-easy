package ui

import (
	"embed"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"path"
)

type FileSystemUI struct {
	views    embed.FS
	fsViews  http.FileSystem
	basePath string
}

func (f FileSystemUI) Open(name string) (http.File, error) {
	fullPath := path.Join(fmt.Sprintf("/%s", f.basePath), name)
	fsFile, err := f.fsViews.Open(
		fullPath[1:],
	)
	if err != nil {
		return nil, err
	}
	return fsFile, nil
}

func (f FileSystemUI) Exists(prefix string, filePath string) bool {
	fullPath := path.Join(prefix, filePath)
	if fullPath == "/" {
		fullPath = fmt.Sprintf("/%s/index.html", f.basePath)
	} else {
		fullPath = path.Join(fmt.Sprintf("/%s", f.basePath), fullPath)
	}
	log.Debugf("FileSystemUI.Exists: %s", fullPath)
	file, err := f.views.Open(fullPath[1:])
	if err != nil {
		return false
	}
	defer file.Close()
	return true
}

func NewFileSystemUI(views embed.FS, basePath string) *FileSystemUI {
	fsViews := http.FS(views)

	return &FileSystemUI{
		basePath: basePath,
		views:    views,
		fsViews:  fsViews,
	}
}
