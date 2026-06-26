var allResults = window.allResults || [];
var chartInstance = null;

// إعدادات ألوان الرسوم في الواجهة الداكنة
Chart.defaults.color = '#7a8caa';
Chart.defaults.borderColor = 'rgba(38,48,80,0.6)';

// يبني الرسوم العامة التي تلخص حالة جميع الموظفين
(function buildSummaryCharts() {
  if (!allResults || !allResults.length) return;

  var high   = allResults.filter(function(r){ return r.level_class === 'high';   }).length;
  var medium = allResults.filter(function(r){ return r.level_class === 'medium'; }).length;
  var low    = allResults.filter(function(r){ return r.level_class === 'low';    }).length;

  var dEl = document.getElementById('donutChart');
  if (dEl) new Chart(dEl.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['High Risk', 'Medium Risk', 'Normal'],
      datasets: [{ data: [high, medium, low],
        backgroundColor: ['rgba(229,57,53,.85)','rgba(251,140,0,.85)','rgba(67,160,71,.85)'],
        borderColor: '#1a2235', borderWidth: 3, hoverOffset: 6 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '66%',
      plugins: {
        legend: { position: 'bottom', labels: { padding: 14, font: { size: 11 }, boxWidth: 11 } },
        tooltip: { callbacks: { label: function(c){ return ' ' + c.label + ': ' + c.parsed + ' employee(s)'; } } }
      }
    }
  });

  var top = allResults.slice(0, Math.min(8, allResults.length));
  var bColors = top.map(function(r){
    return r.level_class==='high' ? 'rgba(229,57,53,.8)' : r.level_class==='medium' ? 'rgba(251,140,0,.8)' : 'rgba(67,160,71,.8)';
  });
  var bEl = document.getElementById('barChart');
  if (bEl) new Chart(bEl.getContext('2d'), {
    type: 'bar',
    data: {
      labels: top.map(function(r){ return r.user; }),
      datasets: [{ label: 'Threat Score (%)',
        data: top.map(function(r){ return parseFloat(r.risk_pct); }),
        backgroundColor: bColors, borderRadius: 5, borderSkipped: false }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        y: { min:0, max:100, ticks: { callback: function(v){ return v+'%'; } }, grid: { color:'rgba(38,48,80,.6)' } },
        x: { grid: { display:false } }
      },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: function(c){ return ' Threat: ' + c.parsed.y.toFixed(0) + '%'; } } }
      }
    }
  });

  var maxLen = 0;
  allResults.forEach(function(r){ if (r.ae_timeline && r.ae_timeline.length > maxLen) maxLen = r.ae_timeline.length; });
  var avgAE = [], avgLSTM = [];
  for (var i = 0; i < maxLen; i++) {
    var sAE = 0, sLSTM = 0, cnt = 0;
    allResults.forEach(function(r){
      if (r.ae_timeline && i < r.ae_timeline.length) { sAE += r.ae_timeline[i]; sLSTM += r.lstm_timeline[i]; cnt++; }
    });
    avgAE.push(cnt ? +(sAE/cnt).toFixed(1) : 0);
    avgLSTM.push(cnt ? +(sLSTM/cnt).toFixed(1) : 0);
  }
  var tLabels = (allResults[0] && allResults[0].timeline_labels)
    ? allResults[0].timeline_labels.slice(0, maxLen)
    : avgAE.map(function(_,i){ return 'P'+(i+1); });
  var tEl = document.getElementById('trendChart');
  if (tEl) new Chart(tEl.getContext('2d'), {
    type: 'line',
    data: {
      labels: tLabels,
      datasets: [
        { label: 'Avg Daily Anomaly', data: avgAE,
          borderColor:'#e53935', backgroundColor:'rgba(229,57,53,.08)',
          fill:true, tension:0.4, pointRadius:3, pointHoverRadius:5, borderWidth:2 },
        { label: 'Avg Sequential Anomaly', data: avgLSTM,
          borderColor:'#4f80ff', backgroundColor:'rgba(79,128,255,.06)',
          fill:true, tension:0.4, pointRadius:3, pointHoverRadius:5, borderWidth:2 }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        y: { min:0, max:100, ticks:{ callback:function(v){ return v+'%'; } }, grid:{ color:'rgba(38,48,80,.6)' } },
        x: { grid:{ color:'rgba(38,48,80,.3)' }, ticks:{ maxTicksLimit:12 } }
      },
      plugins: {
        legend: { labels:{ padding:14, font:{ size:11 }, boxWidth:10 } },
        tooltip: { callbacks:{ label:function(c){ return ' '+c.dataset.label+': '+c.parsed.y.toFixed(1)+'%'; } } }
      }
    }
  });
})();

// يعرض تفاصيل موظف واحد داخل النافذة المنبثقة
function showUser(username) {
  var r = null;
  for (var i = 0; i < allResults.length; i++) {
    if (allResults[i].user === username) { r = allResults[i]; break; }
  }
  if (!r) return;

  document.getElementById('mUser').textContent   = '👤 ' + r.user;
  document.getElementById('mSub').textContent    = (r.department || '') + '  |  ' + (r.role || '') + '  —  Risk: ' + r.level + '  —  ' + r.action;
  document.getElementById('mRisk').textContent   = r.risk_pct;
  document.getElementById('mRisk').style.color   = r.risk_color;
  document.getElementById('mDays').textContent   = r.days_monitored;
  document.getElementById('mLogons').textContent = r.total_logons;
  document.getElementById('mAH').textContent     = r.after_hours;
  document.getElementById('mUSB').textContent    = r.usb_count;
  document.getElementById('mbAE').textContent    = r.ae_pct;
  document.getElementById('mbLSTM').textContent  = r.lstm_pct;
  document.getElementById('mbCTX').textContent   = r.ctx_pct;
  document.getElementById('mbRISK').textContent  = r.risk_pct;
  document.getElementById('mbRISK').style.color  = r.risk_color;

  var tbody = document.getElementById('actBody');
  tbody.innerHTML = '';
  var log = r.activity_log || [];
  for (var j = 0; j < log.length; j++) {
    var d = log[j];
    var susp = d.after_hours || d.usb > 0 || d.files_ext > 0 || d.weekend;
    var rc   = d.anomaly >= 60 ? 'row-danger' : (susp ? 'row-hot' : '');
    var ac   = d.anomaly >= 60 ? '#e53935' : (d.anomaly >= 30 ? '#fb8c00' : '#43a047');
    var aw   = Math.min(d.anomaly, 100);
    tbody.innerHTML +=
      '<tr class="'+rc+'">' +
      '<td>'+d.day+'</td><td>'+d.logons+'</td>' +
      '<td><span class="flag '+(d.after_hours?'flag-yes':'flag-no')+'">'+(d.after_hours?'Yes':'No')+'</span></td>' +
      '<td><span class="flag '+(d.weekend?'flag-yes':'flag-no')+'">'+(d.weekend?'Yes':'No')+'</span></td>' +
      '<td><span class="flag '+(d.usb>0?'flag-usb':'flag-no')+'">'+d.usb+'</span></td>' +
      '<td><span class="flag '+(d.usb_ah>0?'flag-yes':'flag-no')+'">'+d.usb_ah+'</span></td>' +
      '<td>'+d.files+'</td>' +
      '<td><span class="flag '+(d.files_ext>0?'flag-yes':'flag-no')+'">'+d.files_ext+'</span></td>' +
      '<td>'+d.http+'</td><td>'+d.domains+'</td>' +
      '<td><span class="anom-bar"><span class="anom-fill" style="width:'+aw+'%;background:'+ac+'"></span></span>' +
        '<span style="font-size:0.83em;color:'+ac+';font-weight:bold;">'+d.anomaly.toFixed(0)+'%</span></td>' +
      '</tr>';
  }

  try {
    if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
    chartInstance = new Chart(document.getElementById('timelineChart').getContext('2d'), {
      type: 'line',
      data: {
        labels: r.timeline_labels,
        datasets: [
          { label: 'Daily Anomaly (AE)', data: r.ae_timeline,
            borderColor:'#e53935', backgroundColor:'rgba(229,57,53,.1)',
            fill:true, tension:0.35, pointRadius:4, pointHoverRadius:6, borderWidth:2 },
          { label: 'Sequential Anomaly (LSTM)', data: r.lstm_timeline,
            borderColor:'#4f80ff', backgroundColor:'rgba(79,128,255,.08)',
            fill:true, tension:0.35, pointRadius:4, pointHoverRadius:6, borderWidth:2 }
        ]
      },
      options: {
        responsive:true, maintainAspectRatio:false,
        scales: {
          y: { min:0, max:100, ticks:{ callback:function(v){ return v+'%'; } }, grid:{ color:'rgba(38,48,80,.6)' } },
          x: { grid:{ color:'rgba(38,48,80,.3)' }, ticks:{ maxTicksLimit:14 } }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks:{ label:function(c){ return ' '+c.dataset.label+': '+c.parsed.y.toFixed(1)+'%'; } } }
        }
      }
    });
  } catch(e) {
    document.getElementById('timelineChart').parentElement.style.display = 'none';
  }
  document.getElementById('modalOverlay').classList.add('open');
}

// يغلق نافذة التفاصيل عند الضغط خارجها
function closeModal(e) { if (e.target===document.getElementById('modalOverlay')) closeModalDirect(); }
function closeModalDirect() {
  document.getElementById('modalOverlay').classList.remove('open');
  if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
}
document.addEventListener('keydown', function(e){ if (e.key==='Escape') closeModalDirect(); });

// يصدّر نتائج التحليل كملف CSV
function exportCSV() {
  if (!allResults || !allResults.length) return;
  var headers = ['User','Department','Role','Threat Score','Risk Level','Daily Anomaly','Sequential Anomaly',
                 'Suspicious Behavior','Total Logons','After-Hours Logons','USB Connections','Periods Monitored','Recommended Action'];
  var rows = allResults.map(function(r) {
    return ['"'+(r.user||'')+'"', '"'+(r.department||'')+'"', '"'+(r.role||'')+'"',
            r.risk_pct, '"'+r.level+'"', r.ae_pct, r.lstm_pct, r.ctx_pct,
            r.total_logons, r.after_hours, r.usb_count, r.days_monitored, '"'+r.action+'"'].join(',');
  });
  var csv = '\uFEFF' + headers.join(',') + '\n' + rows.join('\n');
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type:'text/csv;charset=utf-8;' }));
  a.download = 'insider_threat_report.csv';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

// يصدّر تقرير الإدارة كملف PDF
function exportPDF() {
  if (!allResults || !allResults.length) return;
  var doc = new window.jspdf.jsPDF({ orientation:'landscape', unit:'mm', format:'a4' });
  var today = new Date().toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' });
  var high = allResults.filter(function(r){ return r.level_class==='high'; }).length;
  var med  = allResults.filter(function(r){ return r.level_class==='medium'; }).length;
  var low_ = allResults.filter(function(r){ return r.level_class==='low'; }).length;

  doc.setFillColor(26,26,46); doc.rect(0,0,297,24,'F');
  doc.setTextColor(255,255,255); doc.setFontSize(14); doc.setFont('helvetica','bold');
  doc.text('Insider Threat Detection — Management Report', 14, 15);
  doc.setFontSize(9); doc.setFont('helvetica','normal');
  doc.text('Generated: '+today, 283, 15, { align:'right' });
  doc.setTextColor(40,40,40); doc.setFontSize(9);
  doc.text('Employees: '+allResults.length+'   High: '+high+'   Medium: '+med+'   Normal: '+low_, 14, 32);

  doc.autoTable({
    head: [['User','Department','Role','Threat %','Risk Level','Daily Anom.','Seq. Anom.','Suspicious','Logons','After-Hrs','USB','Periods','Action']],
    body: allResults.map(function(r) {
      var lvl = r.level_class==='high' ? 'High Risk' : r.level_class==='medium' ? 'Medium Risk' : 'Normal';
      var act = r.level_class==='high' ? 'Immediate Review' : r.level_class==='medium' ? 'Monitor & Verify' : 'No Action Needed';
      return [r.user, r.department||'', r.role||'', r.risk_pct, lvl, r.ae_pct, r.lstm_pct, r.ctx_pct, r.total_logons, r.after_hours, r.usb_count, r.days_monitored, act];
    }),
    startY: 36,
    styles: { fontSize:8, cellPadding:2.5 },
    headStyles: { fillColor:[26,26,46], textColor:255, fontStyle:'bold' },
    bodyStyles: { textColor:40 },
    alternateRowStyles: { fillColor:[248,249,252] },
    didParseCell: function(d) {
      if (d.section==='body' && d.column.index===4) {
        var v = (d.cell.raw||'').toLowerCase();
        d.cell.styles.fontStyle = 'bold';
        d.cell.styles.textColor = v.indexOf('high')>=0 ? [198,40,40] : v.indexOf('medium')>=0 ? [230,81,0] : [46,125,50];
      }
    },
    margin: { left:14, right:14 }
  });
  var pc = doc.internal.getNumberOfPages();
  for (var i=1; i<=pc; i++) {
    doc.setPage(i); doc.setFontSize(7); doc.setTextColor(160,160,160);
    doc.text('Insider Threat Detector — Confidential', 14, 207);
    doc.text('Page '+i+' of '+pc, 283, 207, { align:'right' });
  }
  doc.save('insider_threat_report.pdf');
}
