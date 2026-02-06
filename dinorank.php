<?php
function encode($a)
{
    $data = base64_encode($a);
    for ($i = 0; $i < strlen($data); $i++)
        $data[$i] = chr(ord($data[$i]) + 1);

    return $data;
}

require_once($_SERVER['DOCUMENT_ROOT'] . "/wp-load.php");

$current_user = wp_get_current_user();

// Verificar que el usuario esté logueado
if (!$current_user->ID) {
    header('Location: https://seoconjuntas.net/herramientas-premium/');
    exit;
}

$token = encode($current_user->data->ID . "|" . $current_user->data->user_email . "|" . time());

$dinorank_url = 'https://dinorank.seoconjunta.net/r/' . $token;

if (
    wc_memberships_is_user_active_member($current_user->data->ID, 'plan-mensual')
    || wc_memberships_is_user_active_member($current_user->data->ID, 'plan-trimestral')
    || wc_memberships_is_user_active_member($current_user->data->ID, 'plan-semestral')
    || wc_memberships_is_user_active_member($current_user->data->ID, 'plan-anual')
    || wc_memberships_is_user_active_member($current_user->data->ID, 'semrush-mes')
    || wc_memberships_is_user_active_member($current_user->data->ID, 'plan-lifetime')
) {
    header('Location: ' . $dinorank_url);
    exit;
} else {
    header('Location: https://seoconjuntas.net/herramientas-premium/');
    exit;
}
?>
