package com.znfdev.ida;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.ColorDrawable;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ListView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

/** Generic IDA-style list window (Functions, Strings, Imports, Exports, Names, Segments). */
public class TableView extends LinearLayout {

    public interface RowListener { void onRow(String[] row, boolean longPress); }

    private final String[] titles;
    private final int[] widths;       // in characters
    private final int[] colors;
    private final float charW, rowH;
    private final Paint tp = new Paint(Paint.ANTI_ALIAS_FLAG), bg = new Paint();
    private final ArrayList<String[]> all = new ArrayList<String[]>();
    private final ArrayList<String[]> shown = new ArrayList<String[]>();
    private int sortCol = -1; private boolean sortAsc = true;
    private String filter = "";
    private RowListener listener;
    private final BaseAdapter adapter;
    private final View header;
    private final ListView list;
    private final TextViewLike count;

    /** Tiny label (avoids pulling TextView styling into the dark theme). */
    private static final class TextViewLike extends View {
        String text = ""; final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        TextViewLike(Context c) { super(c); p.setColor(Theme.TEXT_DIM); p.setTextSize(Theme.dp(c, 11)); p.setTypeface(Theme.mono(c)); }
        @Override protected void onMeasure(int w, int h) { setMeasuredDimension(Theme.dp(getContext(), 80), Theme.dp(getContext(), 36)); }
        @Override protected void onDraw(Canvas c) { c.drawText(text, 0, getHeight() / 2f + p.getTextSize() / 3f, p); }
    }

    public TableView(Context c, String[] titles, int[] widths, int[] colors) {
        super(c);
        this.titles = titles; this.widths = widths; this.colors = colors;
        setOrientation(VERTICAL);
        setBackgroundColor(Theme.BG);
        tp.setTypeface(Theme.mono(c));
        tp.setTextSize(Theme.dp(c, 12));
        charW = tp.measureText("0");
        rowH = (float) Math.ceil(tp.getFontSpacing()) + Theme.dp(c, 9);

        // filter row
        LinearLayout bar = new LinearLayout(c);
        bar.setOrientation(HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(Theme.PANEL);
        final EditText f = new EditText(c);
        f.setSingleLine(true);
        f.setHint("Filter");
        f.setTextColor(Theme.TEXT); f.setHintTextColor(Theme.TEXT_DIM);
        f.setTypeface(Theme.mono(c)); f.setTextSize(13);
        f.setBackgroundColor(Theme.BG_ALT);
        f.setPadding(Theme.dp(c, 10), Theme.dp(c, 6), Theme.dp(c, 10), Theme.dp(c, 6));
        f.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence a, int b, int c2, int d) {}
            public void onTextChanged(CharSequence a, int b, int c2, int d) {}
            public void afterTextChanged(Editable e) { filter = e.toString().toLowerCase(); refilter(); }
        });
        LinearLayout.LayoutParams fp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        fp.setMargins(Theme.dp(c, 6), Theme.dp(c, 4), Theme.dp(c, 6), Theme.dp(c, 4));
        bar.addView(f, fp);
        count = new TextViewLike(c);
        bar.addView(count);
        addView(bar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        int total = 0;
        for (int w : widths) total += (int) ((w + 2) * charW);
        final int totalPx = total;

        HorizontalScrollView hs = new HorizontalScrollView(c);
        hs.setFillViewport(true);
        hs.setHorizontalScrollBarEnabled(false);
        LinearLayout col = new LinearLayout(c);
        col.setOrientation(VERTICAL);
        header = new View(c) {
            @Override protected void onDraw(Canvas cv) { drawHeader(cv, getWidth(), getHeight()); }
            @Override protected void onMeasure(int w, int h) { setMeasuredDimension(Math.max(totalPx, MeasureSpec.getSize(w)), (int) rowH); }
            @Override public boolean onTouchEvent(android.view.MotionEvent e) {
                if (e.getAction() == android.view.MotionEvent.ACTION_UP) {
                    float x = e.getX(); float acc = 0;
                    for (int i = 0; i < TableView.this.widths.length; i++) {
                        acc += (TableView.this.widths[i] + 2) * charW;
                        if (x < acc) { sortBy(i); break; }
                    }
                }
                return true;
            }
        };
        col.addView(header, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) rowH));
        list = new ListView(c);
        list.setDivider(null);
        list.setSelector(new ColorDrawable(Theme.PANEL_HI));
        list.setCacheColorHint(0);
        list.setBackgroundColor(Theme.BG);
        adapter = new BaseAdapter() {
            public int getCount() { return shown.size(); }
            public Object getItem(int i) { return shown.get(i); }
            public long getItemId(int i) { return i; }
            public View getView(int i, View cv, ViewGroup p) {
                RowView rv = cv instanceof RowView ? (RowView) cv : new RowView(getContext());
                rv.row = shown.get(i); rv.invalidate();
                return rv;
            }
        };
        list.setAdapter(adapter);
        list.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            public void onItemClick(AdapterView<?> a, View v, int pos, long id) { if (listener != null) listener.onRow(shown.get(pos), false); }
        });
        list.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            public boolean onItemLongClick(AdapterView<?> a, View v, int pos, long id) { if (listener != null) listener.onRow(shown.get(pos), true); return true; }
        });
        col.addView(list, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        hs.addView(col, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.MATCH_PARENT));
        // the column must be at least totalPx wide
        col.setMinimumWidth(totalPx);
        addView(hs, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
    }

    private final class RowView extends View {
        String[] row;
        RowView(Context c) { super(c); }
        @Override protected void onMeasure(int w, int h) {
            int tw = 0; for (int x : widths) tw += (int) ((x + 2) * charW);
            setMeasuredDimension(Math.max(tw, MeasureSpec.getSize(w)), (int) rowH);
        }
        @Override protected void onDraw(Canvas c) {
            if (row == null) return;
            float x = charW, y = rowH / 2f - (tp.descent() + tp.ascent()) / 2f;
            for (int i = 0; i < widths.length && i < row.length; i++) {
                tp.setColor(colors[i]);
                String t = row[i];
                int max = Math.max(widths[i] + 1, 4);
                if (i == widths.length - 1) max = 1000;
                if (t.length() > max) t = t.substring(0, max - 1) + "\u2026";
                c.drawText(t, x, y, tp);
                x += (widths[i] + 2) * charW;
            }
        }
    }

    private void drawHeader(Canvas c, int w, int h) {
        bg.setColor(Theme.PANEL); c.drawRect(0, 0, w, h, bg);
        bg.setColor(Theme.BORDER); c.drawRect(0, h - 1, w, h, bg);
        float x = charW, y = h / 2f - (tp.descent() + tp.ascent()) / 2f;
        for (int i = 0; i < titles.length; i++) {
            tp.setColor(Theme.TEXT);
            String t = titles[i] + (i == sortCol ? (sortAsc ? " \u25B2" : " \u25BC") : "");
            c.drawText(t, x, y, tp);
            x += (widths[i] + 2) * charW;
            bg.setColor(Theme.BORDER); c.drawRect(x - charW, 0, x - charW + 1, h, bg);
        }
    }

    public void setListener(RowListener l) { listener = l; }

    public void setRows(ArrayList<String[]> rows) {
        all.clear(); all.addAll(rows);
        sortCol = -1;
        refilter();
    }

    private void sortBy(int col) {
        if (sortCol == col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
        refilter(); header.invalidate();
    }

    private void refilter() {
        shown.clear();
        if (filter.length() == 0) shown.addAll(all);
        else for (String[] r : all) {
            for (String cell : r) if (cell.toLowerCase().contains(filter)) { shown.add(r); break; }
        }
        if (sortCol >= 0) {
            final int sc = sortCol; final boolean asc = sortAsc;
            Collections.sort(shown, new Comparator<String[]>() {
                public int compare(String[] a, String[] b) {
                    int r = a[sc].compareToIgnoreCase(b[sc]);
                    return asc ? r : -r;
                }
            });
        }
        count.text = shown.size() + "/" + all.size(); count.invalidate();
        adapter.notifyDataSetChanged();
    }
}
