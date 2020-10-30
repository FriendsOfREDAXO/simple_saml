<?php

declare(strict_types=1);

$idp_id = rex_request('idp_id', 'string', null);
$Metadatas = \REDAXO\Simple_SAML\Metadata::getAll();

$content = '';
$content = '<table class="table table-hover">';
$content .= '<thead>
            <th>'.rex_i18n::msg('simple_saml_sp_entity_id').'</th>
            <th>'.rex_i18n::msg('simple_saml_idp_entity_id').'</th>
            <th>'.rex_i18n::msg('simple_saml_func').'</th>
            </thead>';
$content .= '<tbody>';
foreach ($Metadatas as $Metadata) {
    $content .= '<tr class="rex">';
    $content .= '<td>'.$Metadata->getIdentifier().'</td>';
    $content .= '<td>'.$Metadata->getIdp()->getIdentifier().'</td>';
    $content .= '<td><a href="'.rex_url::currentBackendPage(['func' => 'open', 'idp_id' => $Metadata->getIdp()->getIdentifier()]).'">'.rex_i18n::msg('simple_saml_show_item').'</a></td>';
    $content .= '</tr>';
}
$content .= '</tbody>';
$content .= '</table>';

if (0 == count($Metadatas)) {
    $content .= rex_view::info(rex_i18n::msg('simple_saml_no_metadatas_found'));
}

$fragment = new rex_fragment();
$fragment->setVar('title', rex_i18n::msg('simple_saml_metadata_list'), false);
$fragment->setVar('body', $content, false);
$mainContent[] = $fragment->parse('core/page/section.php');

$sideContent = [];

$fragment_title = '...';
$content = '';

if (isset($idp_id)) {
    try {
        $Metadata = \REDAXO\Simple_SAML\Metadata::getByIdp($idp_id);
        $fragment_title = rex_i18n::msg('simple_saml_metadata_defail', $idp_id);

        $content .= '<table class="table table-hover">';

        foreach ($Metadata->getInfoArray() as $Type => $Values) {
            $content .= '<tr><th colspan="2">'.rex_escape($Type).'</th></tr>';
            $content .= '<tr>
            <th>'.rex_i18n::msg('simple_saml_info_type').'</th>
            <th>'.rex_i18n::msg('simple_saml_info_value').'</th>
            </tr>';
            $content .= '<tbody>';
            foreach ($Values as $VType => $Vvalue) {
                $content .= '<tr class="rex">';
                $content .= '<td>'.$VType.'</td>';
                $content .= '<td><code>'.nl2br(rex_escape($Vvalue)).'</code></td>';
                $content .= '</tr>';
            }
            $content .= '</tbody>';
        }
        $content .= '</table><br />';
    } catch (\Exception $e) {
        $content = rex_view::warning(rex_i18n::msg('simple_saml_metadata_not_found', $e->getMessage()));
    }
}

$fragment = new rex_fragment();
$fragment->setVar('title', $fragment_title, false);
$fragment->setVar('body', $content, false);
$sideContent[] = $fragment->parse('core/page/section.php');

// ---------------------- Fragmente

$fragment = new rex_fragment();
$fragment->setVar('content', [implode('', $mainContent), implode('', $sideContent)], false);
$fragment->setVar('classes', ['col-lg-4', 'col-lg-8'], false);
echo $fragment->parse('core/page/grid.php');
