package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Todos (todo_renderer.py)
// ---------------------------------------------------------------------------

var todoMarkers = map[string]string{"pending": "[ ]", "in_progress": "[~]", "done": "[•]"}

var todoTitles = map[string]struct {
	title   string
	color   lipgloss.Color
	loading string
	errMsg  string
}{
	"create_todo":       {"待办", Lavender, "正在创建…", "创建待办失败"},
	"list_todos":        {"待办列表", Lavender, "加载中…", "无法列出待办"},
	"update_todo":       {"待办已更新", Lavender, "正在更新…", "更新待办失败"},
	"mark_todo_done":    {"待办已完成", Lavender, "正在标记完成…", "标记待办完成失败"},
	"mark_todo_pending": {"待办已重新打开", AmberY, "正在重新打开…", "重新打开待办失败"},
	"delete_todo":       {"待办已移除", Slate, "正在移除…", "移除待办失败"},
}

func renderTodo(name string, result any) string {
	meta := todoTitles[name]
	var b strings.Builder
	b.WriteString("📋 " + Bold(meta.color).Render(meta.title))
	if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
		b.WriteString("\n  " + Dim().Render(strings.TrimSpace(s)))
		return b.String()
	}
	if m, ok := result.(map[string]any); ok {
		if truthy(m["success"]) {
			formatTodoLines(&b, m)
		} else {
			errMsg := StringValue(m["error"])
			if errMsg == "" {
				errMsg = meta.errMsg
			}
			b.WriteString("\n  " + Col(Red).Render(errMsg))
		}
	} else {
		b.WriteString("\n  " + Dim().Render(meta.loading))
	}
	return b.String()
}

func formatTodoLines(b *strings.Builder, result map[string]any) {
	todos, ok := result["todos"].([]any)
	if !ok || len(todos) == 0 {
		b.WriteString("\n  " + Dim().Render("暂无待办"))
		return
	}
	for _, t := range todos {
		todo, _ := t.(map[string]any)
		status := StringValue(todo["status"])
		marker := todoMarkers[status]
		if marker == "" {
			marker = todoMarkers["pending"]
		}
		title := strings.TrimSpace(StringValue(todo["title"]))
		if title == "" {
			title = "(无标题)"
		}
		b.WriteString("\n  " + marker + " ")
		switch status {
		case "done":
			b.WriteString(Dim().Strikethrough(true).Render(title))
		case "in_progress":
			b.WriteString(lipgloss.NewStyle().Italic(true).Render(title))
		default:
			b.WriteString(title)
		}
	}
}
